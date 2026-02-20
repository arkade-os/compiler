// Arkade Playground - Main Application
// Import default export for WASM initialization, plus the exported functions
import initWasm, { compile, version, validate, init as initPanicHook } from './pkg/arkade_compiler.js';
import * as contracts from './contracts.js';

// Projects: collections of related contracts
const projects = {
    stability: {
        name: 'Stability',
        description: 'Synthetic USD stablecoins with on-chain price beacon',
        files: {
            'beacon.ark': contracts.price_beacon,
            'offer.ark': contracts.stability_offer,
            'position.ark': contracts.stable_position,
        }
    }
};

// Single file examples
const examples = {
    single_sig: { name: 'SingleSig', code: contracts.single_sig },
    htlc: { name: 'HTLC', code: contracts.htlc },
    fuji_safe: { name: 'FujiSafe', code: contracts.fuji_safe },
    swap: { name: 'NonInteractiveSwap', code: contracts.non_interactive_swap },
    beacon: { name: 'Beacon', code: contracts.beacon },
};

// Global state
let editor = null;
let wasmReady = false;
let currentProject = null;
let currentFile = null;
let openTabs = [];
let fileContents = {}; // Cache of file contents for each open file
let expandedFolders = new Set(); // Track which folders are expanded
let lastCompiledSource = null; // Source that produced the current output

// ── localStorage persistence ──────────────────────────────────────
const STORAGE_KEY = 'arkade-playground';

function saveToStorage() {
    const data = {
        projects: {},
        examples: {}
    };
    // Only save user-created / modified entries
    for (const [id, proj] of Object.entries(projects)) {
        data.projects[id] = { name: proj.name, description: proj.description || '', files: proj.files };
    }
    for (const [id, ex] of Object.entries(examples)) {
        data.examples[id] = { name: ex.name, code: ex.code };
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

function loadFromStorage() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return;
        const data = JSON.parse(raw);
        if (data.projects) {
            for (const [id, proj] of Object.entries(data.projects)) {
                projects[id] = proj;
            }
        }
        if (data.examples) {
            for (const [id, ex] of Object.entries(data.examples)) {
                examples[id] = ex;
            }
        }
    } catch (e) {
        console.warn('Failed to load from localStorage:', e);
    }
}

// ── URL sharing ───────────────────────────────────────────────────

async function compressCode(text) {
    const stream = new CompressionStream('deflate-raw');
    const writer = stream.writable.getWriter();
    writer.write(new TextEncoder().encode(text));
    writer.close();
    const chunks = [];
    const reader = stream.readable.getReader();
    let result;
    while (!(result = await reader.read()).done) chunks.push(result.value);
    const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let i = 0;
    for (const c of chunks) { out.set(c, i); i += c.length; }
    let bin = '';
    for (let j = 0; j < out.length; j++) bin += String.fromCharCode(out[j]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function decompressCode(b64url) {
    const bin = atob(b64url.replace(/-/g, '+').replace(/_/g, '/'));
    const data = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) data[i] = bin.charCodeAt(i);
    const stream = new DecompressionStream('deflate-raw');
    const writer = stream.writable.getWriter();
    writer.write(data);
    writer.close();
    const chunks = [];
    const reader = stream.readable.getReader();
    let result;
    while (!(result = await reader.read()).done) chunks.push(result.value);
    const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let i = 0;
    for (const c of chunks) { out.set(c, i); i += c.length; }
    return new TextDecoder().decode(out);
}

async function shareContract() {
    if (!editor) return;
    const encoded = await compressCode(editor.getValue());
    const url = `${location.origin}${location.pathname}#code=${encoded}`;
    await navigator.clipboard.writeText(url);
    const btn = document.getElementById('share-btn');
    const orig = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i>';
    setTimeout(() => { btn.innerHTML = orig; }, 2000);
}

async function loadFromUrl() {
    if (!location.hash.startsWith('#code=')) return null;
    try {
        return await decompressCode(location.hash.slice(6));
    } catch (e) {
        console.warn('Failed to decode shared contract from URL:', e);
        return null;
    }
}

// ── File management helpers ───────────────────────────────────────

function generateId(name) {
    return name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/(^_|_$)/g, '') || 'untitled';
}

function uniqueId(base, existing) {
    if (!(base in existing)) return base;
    let i = 1;
    while (`${base}_${i}` in existing) i++;
    return `${base}_${i}`;
}

function createFolder(name) {
    const id = uniqueId(generateId(name), projects);
    projects[id] = { name, description: '', files: {} };
    expandedFolders.add(id);
    saveToStorage();
    renderFileTree();
    return id;
}

function createFileInFolder(folderId, fileName) {
    if (!fileName.endsWith('.ark')) fileName += '.ark';
    const project = projects[folderId];
    if (!project) return;
    if (project.files[fileName]) return; // already exists
    const defaultCode = `// ${fileName}\n\noptions {\n  server = serverPk;\n  exit = 144;\n}\n\ncontract MyContract(\n  pubkey user\n) {\n  function spend(signature userSig) {\n    require(checkSig(userSig, user));\n  }\n}\n`;
    project.files[fileName] = defaultCode;
    saveToStorage();
    selectProjectFile(folderId, fileName);
}

function createStandaloneFile(name) {
    if (!name.endsWith('.ark')) name += '.ark';
    const displayName = name.replace(/\.ark$/, '');
    const id = uniqueId(generateId(displayName), examples);
    const defaultCode = `// ${displayName} Contract\n\noptions {\n  server = serverPk;\n  exit = 144;\n}\n\ncontract ${displayName}(\n  pubkey user\n) {\n  function spend(signature userSig) {\n    require(checkSig(userSig, user));\n  }\n}\n`;
    examples[id] = { name: displayName, code: defaultCode };
    expandedFolders.add('_examples');
    saveToStorage();
    selectExample(id);
}

function renameFolder(folderId, newName) {
    const project = projects[folderId];
    if (!project) return;
    project.name = newName;
    saveToStorage();
    renderFileTree();
}

function renameFileInFolder(folderId, oldName, newName) {
    if (!newName.endsWith('.ark')) newName += '.ark';
    const project = projects[folderId];
    if (!project || !project.files[oldName] || oldName === newName) return;
    if (project.files[newName]) return; // target exists

    project.files[newName] = project.files[oldName];
    delete project.files[oldName];

    // Update tabs and cache
    const oldTabId = `${folderId}:${oldName}`;
    const newTabId = `${folderId}:${newName}`;
    const tab = openTabs.find(t => t.id === oldTabId);
    if (tab) {
        tab.id = newTabId;
        tab.file = newName;
        tab.name = newName;
        if (fileContents[oldTabId] !== undefined) {
            fileContents[newTabId] = fileContents[oldTabId];
            delete fileContents[oldTabId];
        }
    }
    if (currentProject === folderId && currentFile === oldName) {
        currentFile = newName;
    }

    saveToStorage();
    updateFileTabs();
    renderFileTree();
    updateCurrentFileName(newName);
}

function renameExample(exampleId, newName) {
    const example = examples[exampleId];
    if (!example) return;
    example.name = newName;

    // Update tab display name
    const tab = openTabs.find(t => t.id === exampleId);
    if (tab) {
        tab.name = `${newName}.ark`;
    }
    if (currentProject === null && currentFile === exampleId) {
        updateCurrentFileName(`${newName}.ark`);
    }

    saveToStorage();
    updateFileTabs();
    renderFileTree();
}

function deleteFolder(folderId) {
    if (!projects[folderId]) return;
    // Close all tabs from this folder
    const tabsToClose = openTabs.filter(t => t.project === folderId).map(t => t.id);
    for (const tabId of tabsToClose) {
        closeTab(tabId);
    }
    delete projects[folderId];
    expandedFolders.delete(folderId);
    saveToStorage();
    renderFileTree();
}

function deleteFileInFolder(folderId, fileName) {
    const project = projects[folderId];
    if (!project || !project.files[fileName]) return;
    const tabId = `${folderId}:${fileName}`;
    closeTab(tabId);
    delete project.files[fileName];
    saveToStorage();
    renderFileTree();
}

function deleteExample(exampleId) {
    if (!examples[exampleId]) return;
    closeTab(exampleId);
    delete examples[exampleId];
    saveToStorage();
    renderFileTree();
}

function moveProjectFileToFolder(fromFolderId, fileName, toFolderId) {
    const fromProject = projects[fromFolderId];
    const toProject   = projects[toFolderId];
    if (!fromProject || !toProject) return;
    if (fromFolderId === toFolderId) return;
    if (!fromProject.files[fileName]) return;

    // Resolve name collision in destination
    const baseName  = fileName.replace(/\.ark$/, '');
    const destFiles = toProject.files;
    let   destName  = fileName;
    if (destName in destFiles) {
        let i = 2;
        while (`${baseName}_${i}.ark` in destFiles) i++;
        destName = `${baseName}_${i}.ark`;
    }

    // Read latest content (prefer in-memory cache to preserve unsaved edits)
    const oldTabId = `${fromFolderId}:${fileName}`;
    const content  = fileContents[oldTabId] !== undefined
                       ? fileContents[oldTabId]
                       : fromProject.files[fileName];

    // Mutate source data
    toProject.files[destName] = content;
    delete fromProject.files[fileName];

    // Remap open tab if present
    const newTabId = `${toFolderId}:${destName}`;
    const tab = openTabs.find(t => t.id === oldTabId);
    if (tab) {
        tab.id      = newTabId;
        tab.project = toFolderId;
        tab.file    = destName;
        tab.name    = destName;
        fileContents[newTabId] = content;
        delete fileContents[oldTabId];
    }

    // Patch active editor state
    if (currentProject === fromFolderId && currentFile === fileName) {
        currentProject = toFolderId;
        currentFile    = destName;
        updateCurrentFileName(destName);
    }

    expandedFolders.add(toFolderId);
    saveToStorage();
    updateFileTabs();
    renderFileTree();
}

function moveProjectFileToExamples(folderId, fileName) {
    const project = projects[folderId];
    if (!project || !project.files[fileName]) return;

    // Read latest content
    const oldTabId = `${folderId}:${fileName}`;
    const content  = fileContents[oldTabId] !== undefined
                       ? fileContents[oldTabId]
                       : project.files[fileName];

    // Derive example id
    const displayName = fileName.replace(/\.ark$/, '');
    const baseId      = generateId(displayName);
    const exampleId   = uniqueId(baseId, examples);

    // Mutate source data
    examples[exampleId] = { name: displayName, code: content };
    delete project.files[fileName];

    // Remap open tab if present
    const tab = openTabs.find(t => t.id === oldTabId);
    if (tab) {
        tab.id      = exampleId;
        tab.project = null;
        tab.file    = exampleId;
        tab.name    = `${displayName}.ark`;
        fileContents[exampleId] = content;
        delete fileContents[oldTabId];
    }

    // Patch active editor state
    if (currentProject === folderId && currentFile === fileName) {
        currentProject = null;
        currentFile    = exampleId;
        updateCurrentFileName(`${displayName}.ark`);
    }

    expandedFolders.add('_examples');
    saveToStorage();
    updateFileTabs();
    renderFileTree();
}

function moveExampleToFolder(exampleId, toFolderId) {
    const example   = examples[exampleId];
    const toProject = projects[toFolderId];
    if (!example || !toProject) return;

    // Read latest content
    const oldTabId = exampleId;
    const content  = fileContents[oldTabId] !== undefined
                       ? fileContents[oldTabId]
                       : example.code;

    // Resolve destination file name
    const baseName = example.name;
    let   destName = `${baseName}.ark`;
    if (destName in toProject.files) {
        let i = 2;
        while (`${baseName}_${i}.ark` in toProject.files) i++;
        destName = `${baseName}_${i}.ark`;
    }

    // Mutate source data
    toProject.files[destName] = content;
    delete examples[exampleId];

    // Remap open tab if present
    const newTabId = `${toFolderId}:${destName}`;
    const tab = openTabs.find(t => t.id === oldTabId);
    if (tab) {
        tab.id      = newTabId;
        tab.project = toFolderId;
        tab.file    = destName;
        tab.name    = destName;
        fileContents[newTabId] = content;
        delete fileContents[oldTabId];
    }

    // Patch active editor state
    if (currentProject === null && currentFile === exampleId) {
        currentProject = toFolderId;
        currentFile    = destName;
        updateCurrentFileName(destName);
    }

    expandedFolders.add(toFolderId);
    saveToStorage();
    updateFileTabs();
    renderFileTree();
}

// ── Context menu ──────────────────────────────────────────────────

let contextMenuTarget = null;

function showContextMenu(e, items) {
    e.preventDefault();
    const menu = document.getElementById('context-menu');
    let html = '';
    for (const item of items) {
        if (item.separator) {
            html += '<div class="context-menu-separator"></div>';
        } else {
            const cls = item.danger ? 'context-menu-item danger' : 'context-menu-item';
            html += `<div class="${cls}" data-action="${item.action}">
                <i class="fas ${item.icon}"></i> ${item.label}
            </div>`;
        }
    }
    menu.innerHTML = html;

    // Position
    menu.style.left = `${e.clientX}px`;
    menu.style.top = `${e.clientY}px`;
    menu.classList.add('visible');

    // Ensure menu stays within viewport
    requestAnimationFrame(() => {
        const rect = menu.getBoundingClientRect();
        if (rect.right > window.innerWidth) {
            menu.style.left = `${window.innerWidth - rect.width - 4}px`;
        }
        if (rect.bottom > window.innerHeight) {
            menu.style.top = `${window.innerHeight - rect.height - 4}px`;
        }
    });

    // Action handlers
    menu.querySelectorAll('.context-menu-item').forEach(el => {
        el.addEventListener('click', () => {
            hideContextMenu();
            handleContextAction(el.dataset.action);
        });
    });
}

function hideContextMenu() {
    document.getElementById('context-menu').classList.remove('visible');
}

function handleContextAction(action) {
    const t = contextMenuTarget;
    contextMenuTarget = null;
    if (!t) return;

    switch (action) {
        case 'new-file-in-folder':
            promptNewFileInFolder(t.folderId);
            break;
        case 'rename-folder':
            startInlineRename('folder', t.folderId);
            break;
        case 'delete-folder':
            if (confirm(`Delete folder "${projects[t.folderId]?.name}" and all its files?`)) {
                deleteFolder(t.folderId);
            }
            break;
        case 'rename-file':
            if (t.folderId) {
                startInlineRename('project-file', t.folderId, t.fileName);
            } else {
                startInlineRename('example', t.exampleId);
            }
            break;
        case 'delete-file':
            if (t.folderId) {
                if (confirm(`Delete "${t.fileName}"?`)) {
                    deleteFileInFolder(t.folderId, t.fileName);
                }
            } else {
                if (confirm(`Delete "${examples[t.exampleId]?.name}.ark"?`)) {
                    deleteExample(t.exampleId);
                }
            }
            break;
        case 'new-file':
            promptNewStandaloneFile();
            break;
        case 'new-folder':
            promptNewFolder();
            break;
    }
}

// ── Inline rename ─────────────────────────────────────────────────

function startInlineRename(type, id, fileName) {
    renderFileTree(); // reset any existing rename inputs
    let el;

    if (type === 'folder') {
        el = document.querySelector(`.tree-folder[data-folder="${id}"]`);
        if (!el) return;
        const currentName = projects[id]?.name || id;
        const input = document.createElement('input');
        input.className = 'tree-rename-input';
        input.value = currentName;
        el.textContent = '';
        el.appendChild(input);
        input.focus();
        input.select();
        const commit = () => {
            const val = input.value.trim();
            if (val && val !== currentName) renameFolder(id, val);
            else renderFileTree();
        };
        input.addEventListener('blur', commit);
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
            if (e.key === 'Escape') { input.value = currentName; input.blur(); }
        });
    } else if (type === 'project-file') {
        el = document.querySelector(`.tree-item[data-project="${id}"][data-file="${fileName}"]`);
        if (!el) return;
        const input = document.createElement('input');
        input.className = 'tree-rename-input';
        input.value = fileName;
        el.textContent = '';
        el.appendChild(input);
        input.focus();
        input.select();
        const commit = () => {
            let val = input.value.trim();
            if (val && val !== fileName) renameFileInFolder(id, fileName, val);
            else renderFileTree();
        };
        input.addEventListener('blur', commit);
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
            if (e.key === 'Escape') { input.value = fileName; input.blur(); }
        });
    } else if (type === 'example') {
        el = document.querySelector(`.tree-item[data-example="${id}"]`);
        if (!el) return;
        const currentName = examples[id]?.name || id;
        const input = document.createElement('input');
        input.className = 'tree-rename-input';
        input.value = currentName;
        el.textContent = '';
        el.appendChild(input);
        input.focus();
        input.select();
        const commit = () => {
            const val = input.value.trim();
            if (val && val !== currentName) renameExample(id, val);
            else renderFileTree();
        };
        input.addEventListener('blur', commit);
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
            if (e.key === 'Escape') { input.value = currentName; input.blur(); }
        });
    }
}

// ── Prompt dialogs for new items ──────────────────────────────────

function promptNewFolder() {
    const name = prompt('New folder name:');
    if (name && name.trim()) createFolder(name.trim());
}

function promptNewFileInFolder(folderId) {
    const name = prompt('New file name (e.g. contract.ark):');
    if (name && name.trim()) createFileInFolder(folderId, name.trim());
}

function promptNewStandaloneFile() {
    const name = prompt('New file name (e.g. MyContract.ark):');
    if (name && name.trim()) createStandaloneFile(name.trim());
}

// Initialize WASM module
async function initCompiler() {
    try {
        await initWasm();
        initPanicHook();
        wasmReady = true;

        const ver = version();
        document.getElementById('compiler-version').textContent = `v${ver}`;
        document.getElementById('footer-version').textContent = `v${ver}`;

        // Show button as ready to compile
        markDirty();
    } catch (err) {
        console.error('Failed to initialize WASM:', err);
        showError('Failed to load compiler. Make sure the WASM module is built.');
    }
}

// Render file tree
function renderFileTree() {
    const container = document.getElementById('file-tree');
    let html = '';

    // Examples folder (contains project sub-folders + standalone examples)
    const examplesExpanded = expandedFolders.has('_examples');
    html += `<div class="tree-folder" data-folder="_examples">
        <i class="fas ${examplesExpanded ? 'fa-chevron-down' : 'fa-chevron-right'}"></i>
        <i class="fas fa-folder${examplesExpanded ? '-open' : ''}"></i>
        Examples
    </div>`;
    html += `<div class="tree-folder-content ${examplesExpanded ? 'expanded' : ''}" data-folder="_examples">`;

    // Project sub-folders nested inside Examples
    for (const [id, project] of Object.entries(projects)) {
        const isExpanded = expandedFolders.has(id);
        html += `<div class="tree-folder" data-folder="${id}">
            <i class="fas ${isExpanded ? 'fa-chevron-down' : 'fa-chevron-right'}"></i>
            <i class="fas fa-folder${isExpanded ? '-open' : ''}"></i>
            ${project.name}
        </div>`;
        html += `<div class="tree-folder-content ${isExpanded ? 'expanded' : ''}" data-folder="${id}">`;
        for (const fileName of Object.keys(project.files)) {
            const isActive = currentProject === id && currentFile === fileName;
            html += `<div class="tree-item ${isActive ? 'active' : ''}" data-project="${id}" data-file="${fileName}" draggable="true">
                <i class="fas fa-file-code"></i>
                ${fileName}
            </div>`;
        }
        html += '</div>';
    }

    // Standalone examples
    for (const [id, example] of Object.entries(examples)) {
        const isActive = currentProject === null && currentFile === id;
        html += `<div class="tree-item ${isActive ? 'active' : ''}" data-example="${id}" draggable="true">
            <i class="fas fa-file-code"></i>
            ${example.name}.ark
        </div>`;
    }
    html += '</div>';

    container.innerHTML = html;

    // Add click handlers for folders
    container.querySelectorAll('.tree-folder').forEach(folder => {
        folder.addEventListener('click', () => {
            const folderId = folder.dataset.folder;
            toggleFolder(folderId);
        });
        // Right-click context menu for folders
        folder.addEventListener('contextmenu', (e) => {
            e.stopPropagation();
            const folderId = folder.dataset.folder;
            if (folderId === '_examples') {
                contextMenuTarget = { type: 'examples-folder' };
                showContextMenu(e, [
                    { action: 'new-file', icon: 'fa-file-circle-plus', label: 'New File' }
                ]);
            } else {
                contextMenuTarget = { type: 'folder', folderId };
                showContextMenu(e, [
                    { action: 'new-file-in-folder', icon: 'fa-file-circle-plus', label: 'New File' },
                    { separator: true },
                    { action: 'rename-folder', icon: 'fa-pen', label: 'Rename' },
                    { action: 'delete-folder', icon: 'fa-trash', label: 'Delete', danger: true }
                ]);
            }
        });
        // Drag-and-drop: folder header as drop target
        folder.addEventListener('dragover', (e) => {
            if (!e.dataTransfer.types.includes('text/plain')) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            folder.classList.add('drag-over');
        });
        folder.addEventListener('dragleave', (e) => {
            if (folder.contains(e.relatedTarget)) return;
            folder.classList.remove('drag-over');
        });
        folder.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            folder.classList.remove('drag-over');
            const raw = e.dataTransfer.getData('text/plain');
            if (!raw) return;
            const targetFolderId = folder.dataset.folder;
            const parts = raw.split('|');
            if (parts[0] === 'project-file') {
                const fromFolderId = parts[1];
                const fileName     = parts[2];
                if (targetFolderId === '_examples') {
                    moveProjectFileToExamples(fromFolderId, fileName);
                } else {
                    moveProjectFileToFolder(fromFolderId, fileName, targetFolderId);
                }
            } else if (parts[0] === 'example') {
                if (targetFolderId === '_examples') return;
                moveExampleToFolder(parts[1], targetFolderId);
            }
        });
    });

    // Drag-and-drop: folder content area as drop target
    container.querySelectorAll('.tree-folder-content').forEach(content => {
        const folderId = content.dataset.folder;
        content.addEventListener('dragover', (e) => {
            if (!e.dataTransfer.types.includes('text/plain')) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            content.classList.add('drag-over');
        });
        content.addEventListener('dragleave', (e) => {
            if (content.contains(e.relatedTarget)) return;
            content.classList.remove('drag-over');
        });
        content.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            content.classList.remove('drag-over');
            const raw = e.dataTransfer.getData('text/plain');
            if (!raw) return;
            const parts = raw.split('|');
            if (parts[0] === 'project-file') {
                const fromFolderId = parts[1];
                const fileName     = parts[2];
                if (folderId === '_examples') {
                    moveProjectFileToExamples(fromFolderId, fileName);
                } else {
                    moveProjectFileToFolder(fromFolderId, fileName, folderId);
                }
            } else if (parts[0] === 'example') {
                if (folderId === '_examples') return;
                moveExampleToFolder(parts[1], folderId);
            }
        });
    });

    container.querySelectorAll('.tree-item[data-project]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.stopPropagation();
            selectProjectFile(item.dataset.project, item.dataset.file);
        });
        // Right-click context menu for project files
        item.addEventListener('contextmenu', (e) => {
            e.stopPropagation();
            contextMenuTarget = { type: 'project-file', folderId: item.dataset.project, fileName: item.dataset.file };
            showContextMenu(e, [
                { action: 'rename-file', icon: 'fa-pen', label: 'Rename' },
                { action: 'delete-file', icon: 'fa-trash', label: 'Delete', danger: true }
            ]);
        });
        // Drag-and-drop: project file as drag source
        item.addEventListener('dragstart', (e) => {
            e.stopPropagation();
            e.dataTransfer.setData('text/plain', `project-file|${item.dataset.project}|${item.dataset.file}`);
            e.dataTransfer.effectAllowed = 'move';
            item.classList.add('dragging');
        });
        item.addEventListener('dragend', () => {
            item.classList.remove('dragging');
            container.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));
        });
    });

    container.querySelectorAll('.tree-item[data-example]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.stopPropagation();
            selectExample(item.dataset.example);
        });
        // Right-click context menu for example files
        item.addEventListener('contextmenu', (e) => {
            e.stopPropagation();
            contextMenuTarget = { type: 'example', exampleId: item.dataset.example };
            showContextMenu(e, [
                { action: 'rename-file', icon: 'fa-pen', label: 'Rename' },
                { action: 'delete-file', icon: 'fa-trash', label: 'Delete', danger: true }
            ]);
        });
        // Drag-and-drop: example as drag source
        item.addEventListener('dragstart', (e) => {
            e.stopPropagation();
            e.dataTransfer.setData('text/plain', `example|${item.dataset.example}`);
            e.dataTransfer.effectAllowed = 'move';
            item.classList.add('dragging');
        });
        item.addEventListener('dragend', () => {
            item.classList.remove('dragging');
            container.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));
        });
    });
}

// Toggle folder expansion
function toggleFolder(folderId) {
    if (expandedFolders.has(folderId)) {
        expandedFolders.delete(folderId);
    } else {
        expandedFolders.add(folderId);
    }
    renderFileTree();
}

// Select a file from a project
function selectProjectFile(projectId, fileName) {
    // Save current file content
    saveCurrentFile();

    // Expand the folder
    expandedFolders.add(projectId);

    currentProject = projectId;
    currentFile = fileName;

    const project = projects[projectId];
    const code = project.files[fileName];

    // Update open tabs
    const tabId = `${projectId}:${fileName}`;
    if (!openTabs.find(t => t.id === tabId)) {
        openTabs.push({ id: tabId, project: projectId, file: fileName, name: fileName });
    }
    fileContents[tabId] = code;

    if (editor) {
        editor.setValue(code);
    }

    updateFileTabs();
    renderFileTree();
    updateCurrentFileName(fileName);
    lastCompiledSource = null;
    markDirty();
}

// Select a single-file example
function selectExample(exampleId) {
    // Save current file content
    saveCurrentFile();

    // Expand the examples folder
    expandedFolders.add('_examples');

    currentProject = null;
    currentFile = exampleId;

    const example = examples[exampleId];

    // Update open tabs
    const tabId = exampleId;
    if (!openTabs.find(t => t.id === tabId)) {
        openTabs.push({ id: tabId, project: null, file: exampleId, name: `${example.name}.ark` });
    }
    fileContents[tabId] = example.code;

    if (editor) {
        editor.setValue(example.code);
    }

    updateFileTabs();
    renderFileTree();
    updateCurrentFileName(`${example.name}.ark`);
    lastCompiledSource = null;
    markDirty();
}

// Save current file content to cache and source data
function saveCurrentFile() {
    if (!editor) return;

    let tabId;
    if (currentProject) {
        tabId = `${currentProject}:${currentFile}`;
    } else if (currentFile) {
        tabId = currentFile;
    }

    if (tabId) {
        const content = editor.getValue();
        fileContents[tabId] = content;

        // Persist back to source data
        if (currentProject && projects[currentProject]) {
            projects[currentProject].files[currentFile] = content;
        } else if (currentFile && examples[currentFile]) {
            examples[currentFile].code = content;
        }
        saveToStorage();
    }
}

// Update file tabs UI
function updateFileTabs() {
    const container = document.getElementById('file-tabs');
    if (openTabs.length === 0) {
        container.innerHTML = '';
        return;
    }

    let activeTabId;
    if (currentProject) {
        activeTabId = `${currentProject}:${currentFile}`;
    } else {
        activeTabId = currentFile;
    }

    let html = '';
    for (const tab of openTabs) {
        const isActive = tab.id === activeTabId;
        html += `<span class="file-tab ${isActive ? 'active' : ''}" data-tab="${tab.id}">
            <i class="fas fa-file-code"></i>
            <span class="tab-name">${tab.name}</span>
            <i class="fas fa-times tab-close" data-tab="${tab.id}"></i>
        </span>`;
    }
    container.innerHTML = html;

    // Add click handlers for tabs
    container.querySelectorAll('.file-tab').forEach(tabEl => {
        tabEl.addEventListener('click', (e) => {
            if (e.target.classList.contains('tab-close')) {
                closeTab(tabEl.dataset.tab);
            } else {
                switchToTab(tabEl.dataset.tab);
            }
        });
    });
}

// Switch to a tab
function switchToTab(tabId) {
    saveCurrentFile();

    const tab = openTabs.find(t => t.id === tabId);
    if (!tab) return;

    currentProject = tab.project;
    currentFile = tab.file;

    const content = fileContents[tabId];
    if (content !== undefined && editor) {
        editor.setValue(content);
    }

    updateFileTabs();
    renderFileTree();
    updateCurrentFileName(tab.name);
    lastCompiledSource = null;
    markDirty();
}

// Close a tab
function closeTab(tabId) {
    const idx = openTabs.findIndex(t => t.id === tabId);
    if (idx === -1) return;

    openTabs.splice(idx, 1);
    delete fileContents[tabId];

    // If closing active tab, switch to another
    const activeTabId = currentProject ? `${currentProject}:${currentFile}` : currentFile;
    if (tabId === activeTabId) {
        if (openTabs.length > 0) {
            const newTab = openTabs[Math.min(idx, openTabs.length - 1)];
            switchToTab(newTab.id);
            return;
        } else {
            // No tabs left, load default
            selectExample('single_sig');
            return;
        }
    }

    updateFileTabs();
}

// Update current file name display
function updateCurrentFileName(name) {
    document.getElementById('current-file').textContent = name;
}

// Initialize Monaco Editor
function initMonaco() {
    require.config({
        paths: {
            'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs'
        }
    });

    require(['vs/editor/editor.main'], function() {
        // Register Arkade language
        monaco.languages.register({ id: 'arkade' });

        // Set tokenizer (Monarch definition)
        monaco.languages.setMonarchTokensProvider('arkade', window.arkadeMonarch);

        // Set language configuration
        monaco.languages.setLanguageConfiguration('arkade', window.arkadeLanguageConfig);

        // Register completions
        monaco.languages.registerCompletionItemProvider('arkade', {
            provideCompletionItems: (model, position) => {
                const suggestions = window.arkadeCompletions.map(item => ({
                    label: item.label,
                    kind: monaco.languages.CompletionItemKind[item.kind] || monaco.languages.CompletionItemKind.Text,
                    insertText: item.insertText,
                    insertTextRules: item.insertTextRules ? monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet : undefined,
                    detail: item.detail || '',
                    range: {
                        startLineNumber: position.lineNumber,
                        startColumn: position.column,
                        endLineNumber: position.lineNumber,
                        endColumn: position.column
                    }
                }));
                return { suggestions };
            }
        });

        // Define theme
        monaco.editor.defineTheme('arkade-dark', window.arkadeTheme);

        // Create editor
        editor = monaco.editor.create(document.getElementById('editor'), {
            value: examples.single_sig.code,
            language: 'arkade',
            theme: 'arkade-dark',
            automaticLayout: true,
            minimap: { enabled: false },
            fontSize: 14,
            lineNumbers: 'on',
            renderLineHighlight: 'all',
            scrollBeyondLastLine: false,
            wordWrap: 'on',
            tabSize: 2,
            insertSpaces: true,
            folding: true,
            bracketPairColorization: { enabled: true }
        });

        // Keyboard shortcut: Ctrl+Enter to compile
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => {
            doCompile();
        });

        // Mark dirty on change — no auto-compile
        editor.onDidChangeModelContent(() => {
            if (editor.getValue() !== lastCompiledSource) {
                markDirty();
            }
        });

        // Load shared contract from URL hash if present
        window._urlCodePromise.then(urlCode => {
            if (urlCode) {
                const id = uniqueId('shared', examples);
                examples[id] = { name: 'Shared', code: urlCode };
                saveToStorage();
                selectExample(id);
                history.replaceState(null, '', location.pathname + location.search);
            }
        });

        // Initialize WASM after editor is ready
        initCompiler();
    });
}

// Mark the editor as having uncompiled changes
function markDirty() {
    const btn = document.getElementById('compile-btn');
    // Re-trigger animation by removing and re-adding the class
    btn.classList.remove('compiled', 'needs-compile');
    void btn.offsetWidth; // reflow to restart animation
    btn.classList.add('needs-compile');

    const statusEl = document.getElementById('compile-status');
    statusEl.textContent = '';
    statusEl.className = 'compile-status';
}

// Mark the editor as up-to-date with compiled output
function markCompiled() {
    const btn = document.getElementById('compile-btn');
    btn.classList.remove('needs-compile');
    btn.classList.add('compiled');
}

// Compile the source code
function doCompile() {
    if (!wasmReady || !editor) return;

    const source = editor.getValue();
    clearErrors();

    try {
        const result = compile(source);
        lastCompiledSource = source;
        displayJson(result);
        displayAsm(result);
        showSuccess(result);
        markCompiled();
    } catch (err) {
        showError(err.toString());
    }
}

// Display JSON output
function displayJson(jsonStr) {
    const container = document.getElementById('json-output');
    container.innerHTML = syntaxHighlightJson(jsonStr);
}

// Syntax highlight JSON
function syntaxHighlightJson(json) {
    if (typeof json !== 'string') {
        json = JSON.stringify(json, null, 2);
    }

    return json
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, match => {
            let cls = 'json-number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'json-key';
                    match = match.slice(0, -1); // Remove colon
                    return `<span class="${cls}">${match}</span>:`;
                } else {
                    cls = 'json-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'json-boolean';
            } else if (/null/.test(match)) {
                cls = 'json-null';
            }
            return `<span class="${cls}">${match}</span>`;
        });
}

// Display Assembly output
function displayAsm(jsonStr) {
    const container = document.getElementById('asm-output');

    try {
        const data = JSON.parse(jsonStr);
        let html = '';

        if (data.functions && data.functions.length > 0) {
            for (const func of data.functions) {
                const variant = func.serverVariant ? 'Cooperative' : 'Exit';
                html += `<span class="asm-function">${func.name} <span class="asm-variant">(${variant} path)</span></span>\n`;

                if (func.asm) {
                    html += highlightAsm(func.asm) + '\n\n';
                }
            }
        } else {
            html = '<span class="comment">No functions compiled</span>';
        }

        container.innerHTML = html;
    } catch (e) {
        container.textContent = 'Failed to parse assembly output';
    }
}

// Highlight assembly code
function highlightAsm(asm) {
    const tokens = Array.isArray(asm) ? asm : asm.split(' ');
    return tokens
        .map(token => {
            if (token.startsWith('OP_')) {
                return `<span class="asm-opcode">${token}</span>`;
            } else if (token.startsWith('<') && token.endsWith('>')) {
                return `<span class="asm-placeholder">${token}</span>`;
            }
            return token;
        })
        .join(' ');
}

// Show compilation success
function showSuccess(jsonStr) {
    const statusEl = document.getElementById('compile-status');
    let funcCount = '';
    try {
        const data = JSON.parse(jsonStr);
        const count = data.functions?.length || 0;
        funcCount = ` &mdash; ${count} function${count !== 1 ? 's' : ''}`;
    } catch (e) {}
    statusEl.innerHTML = `<i class="fas fa-check-circle"></i> Compiled${funcCount}`;
    statusEl.className = 'compile-status success';
}

// Show error
function showError(message) {
    const statusEl = document.getElementById('compile-status');
    statusEl.innerHTML = `<i class="fas fa-times-circle"></i> Error`;
    statusEl.className = 'compile-status error';

    const errorsTab = document.getElementById('errors-output');
    const errorCount = document.getElementById('error-count');

    errorsTab.textContent = message;
    errorCount.textContent = '1';
    errorCount.classList.add('visible');

    // Switch to errors tab
    switchTab('errors');

    // Highlight line if possible
    const lineMatch = message.match(/line (\d+)/i);
    if (lineMatch && editor) {
        const lineNumber = parseInt(lineMatch[1], 10);
        editor.revealLineInCenter(lineNumber);
        editor.setSelection({
            startLineNumber: lineNumber,
            startColumn: 1,
            endLineNumber: lineNumber,
            endColumn: 1000
        });
    }
}

// Clear errors
function clearErrors() {
    document.getElementById('errors-output').textContent = '';
    document.getElementById('error-count').textContent = '';
    document.getElementById('error-count').classList.remove('visible');
    const statusEl = document.getElementById('compile-status');
    statusEl.textContent = '';
    statusEl.className = 'compile-status';
}

// Switch output tab
function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });

    // Update tab content
    document.querySelectorAll('.output-tab').forEach(content => {
        content.classList.toggle('active', content.id === `${tabName}-output`);
    });
}

// Copy to clipboard
async function copyOutput() {
    const activeTab = document.querySelector('.output-tab.active');
    if (!activeTab) return;

    const text = activeTab.textContent;
    try {
        await navigator.clipboard.writeText(text);
        // Visual feedback
        const btn = document.getElementById('copy-btn');
        btn.innerHTML = '<i class="fas fa-check"></i>';
        setTimeout(() => {
            btn.innerHTML = '<i class="fas fa-copy"></i>';
        }, 1500);
    } catch (err) {
        console.error('Failed to copy:', err);
    }
}

// Resizable panels
function initResizer() {
    const divider = document.getElementById('divider');
    const editorPanel = document.querySelector('.editor-panel');
    let isResizing = false;

    divider.addEventListener('mousedown', (e) => {
        isResizing = true;
        divider.classList.add('dragging');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;

        const containerWidth = document.querySelector('main').offsetWidth;
        const newWidth = (e.clientX / containerWidth) * 100;

        if (newWidth > 20 && newWidth < 80) {
            editorPanel.style.flex = `0 0 ${newWidth}%`;
        }
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            divider.classList.remove('dragging');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }
    });
}

// Initialize sidebar resizer
function initSidebarResizer() {
    const divider = document.getElementById('sidebar-divider');
    const sidebar = document.getElementById('sidebar');
    let isResizing = false;

    divider.addEventListener('mousedown', (e) => {
        isResizing = true;
        divider.classList.add('dragging');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;

        const newWidth = e.clientX;
        if (newWidth > 150 && newWidth < 400) {
            sidebar.style.width = `${newWidth}px`;
        }
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            divider.classList.remove('dragging');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }
    });
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Load user data from localStorage
    loadFromStorage();

    // Begin decoding URL hash early (async) so it's ready when Monaco is up
    window._urlCodePromise = loadFromUrl();

    // Expand Examples folder by default
    expandedFolders.add('_examples');

    // Render file tree
    renderFileTree();

    // Set initial file state
    currentFile = 'single_sig';
    openTabs.push({ id: 'single_sig', project: null, file: 'single_sig', name: 'SingleSig.ark' });
    fileContents['single_sig'] = examples.single_sig.code;
    updateFileTabs();

    // Initialize Monaco
    initMonaco();

    // Initialize resizers
    initResizer();
    initSidebarResizer();

    // Tab switching (output tabs)
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    // Compile button
    document.getElementById('compile-btn').addEventListener('click', doCompile);

    // Cmd/Ctrl+S → compile (prevent browser save dialog)
    document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 's') {
            e.preventDefault();
            doCompile();
        }
    });

    // Copy button
    document.getElementById('copy-btn').addEventListener('click', copyOutput);

    // Share button
    document.getElementById('share-btn').addEventListener('click', shareContract);

    // Sidebar action buttons
    document.getElementById('new-file-btn').addEventListener('click', promptNewStandaloneFile);
    document.getElementById('new-folder-btn').addEventListener('click', promptNewFolder);

    // Dismiss context menu on click outside
    document.addEventListener('click', hideContextMenu);
    document.addEventListener('contextmenu', (e) => {
        // Only hide if clicking outside the file tree
        if (!e.target.closest('.file-tree') && !e.target.closest('.context-menu')) {
            hideContextMenu();
        }
    });
});
