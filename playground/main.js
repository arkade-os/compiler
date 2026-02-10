// Arkade Playground - Main Application
// Import default export for WASM initialization, plus the exported functions
import initWasm, { compile, version, validate, init as initPanicHook } from './pkg/arkade_compiler.js';

// Projects: collections of related contracts
const projects = {
    dex: {
        name: 'DEX',
        description: 'Decentralized Exchange with non-interactive swaps',
        files: {
            'swap.ark': `// Non-Interactive Swap Contract
// Allows users to exchange assets without requiring both parties to be online simultaneously.
//
// Paths:
// - swap cooperative: takerSig + serverSig + OP_INSPECT* (trustless via introspection)
// - swap exit: makerSig + takerSig + CSV (N-of-N users, pure Bitcoin)
// - cancel cooperative: makerSig + serverSig + after(expiration)
// - cancel exit: makerSig + after(expiration) + CSV

options {
  server = serverPk;
  exit = 144;
}

contract NonInteractiveSwap(
  pubkey makerPk,
  bytes32 offerAssetId,
  int offerAmount,
  bytes32 wantAssetId,
  int wantAmount,
  int expirationTime
) {
  // Swap: Any taker can fulfill
  function swap(pubkey takerPk, signature takerSig) {
    require(checkSig(takerSig, takerPk), "invalid taker signature");

    // Output 0: maker receives wantAsset
    require(
      tx.outputs[0].assets.lookup(wantAssetId) >= wantAmount,
      "insufficient want asset for maker"
    );
    require(
      tx.outputs[0].scriptPubKey == new P2TR(makerPk),
      "output 0 not spendable by maker"
    );

    // Output 1: taker receives offerAsset
    require(
      tx.outputs[1].assets.lookup(offerAssetId) >= offerAmount,
      "insufficient offer asset for taker"
    );
    require(
      tx.outputs[1].scriptPubKey == new P2TR(takerPk),
      "output 1 not spendable by taker"
    );
  }

  // Cancel: Maker reclaims after expiration
  function cancel(signature makerSig) {
    require(tx.time >= expirationTime, "swap not expired");
    require(checkSig(makerSig, makerPk), "invalid maker signature");
  }
}`,
            'beacon.ark': `// Price Beacon Contract
// Read-only recursive covenant that ensures all asset groups survive intact.
// Use cases: Price oracle beacons, passthrough covenants

options {
  server = oracleServerPk;
  exit = 144;
}

contract PriceBeacon(
  bytes32 ctrlAssetId,
  pubkey oraclePk,
  int numGroups
) {
  // Anyone can pass through - all groups must survive
  function passthrough() {
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");

    for (k, group) in tx.assetGroups {
      require(group.sumOutputs >= group.sumInputs, "drained");
    }
  }

  // Oracle updates price (quantity encodes value)
  function update(signature oracleSig) {
    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl");
    require(tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey, "broken");
    require(checkSig(oracleSig, oraclePk), "bad sig");
  }
}`
        }
    },
    stability: {
        name: 'Stability',
        description: 'Synthetic USD stablecoins with on-chain price beacon',
        files: {
            'beacon.ark': `// Price Beacon Contract
// On-chain price oracle using asset quantity as price.
// Quantity of priceAssetId = BTC/USD price in cents.

options {
  server = oraclePk;
  exit = 144;
}

contract PriceBeacon(
  bytes32 priceAssetId,      // Asset whose quantity = price
  pubkey oraclePk            // Oracle authorized to update
) {
  // Anyone can read price via passthrough
  function passthrough() {
    require(
      tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey,
      "beacon must survive"
    );
    int currentPrice = tx.input.current.assets.lookup(priceAssetId);
    require(
      tx.outputs[0].assets.lookup(priceAssetId) >= currentPrice,
      "price asset must survive"
    );
  }

  // Oracle updates the price
  function update(signature oracleSig, int newPrice) {
    require(checkSig(oracleSig, oraclePk), "invalid oracle signature");
    require(newPrice > 0, "price must be positive");
    require(
      tx.outputs[0].scriptPubKey == tx.input.current.scriptPubKey,
      "beacon must survive"
    );
    require(
      tx.outputs[0].assets.lookup(priceAssetId) == newPrice,
      "price not updated"
    );
  }
}`,
            'offer.ark': `// Stability Offer Contract
// Provider pre-commits liquidity to specific user.
// Uses PriceBeacon for on-chain price discovery.

options {
  server = providerPk;
  exit = 144;
}

contract StabilityOffer(
  pubkey providerPk,
  pubkey userPk,             // User this offer is for
  bytes32 priceAssetId,
  int entryPriceUSD,
  int collateralBTC,
  int maxExposureBTC
) {
  // Anyone can execute - offer pre-committed to userPk
  function take(int userBTC) {
    require(userBTC > 0, "zero deposit");
    require(userBTC <= maxExposureBTC, "exceeds capacity");

    int stableUSD = userBTC * entryPriceUSD / 100000000;
    int totalCollateral = userBTC + collateralBTC;

    require(
      tx.outputs[0].scriptPubKey == new StablePosition(
        userPk, providerPk, priceAssetId,
        stableUSD, entryPriceUSD, totalCollateral
      ),
      "invalid position"
    );
    require(tx.outputs[0].value >= totalCollateral, "insufficient collateral");

    int remaining = maxExposureBTC - userBTC;
    if (remaining > 0) {
      require(
        tx.outputs[1].scriptPubKey == new StabilityOffer(
          providerPk, userPk, priceAssetId,
          entryPriceUSD, collateralBTC, remaining
        ),
        "invalid remaining offer"
      );
    }
  }

  function withdraw(signature providerSig) {
    require(checkSig(providerSig, providerPk), "invalid signature");
  }
}`,
            'position.ark': `// Stable Position Contract
// User holds fixed USD value backed by BTC.
// Reads price from PriceBeacon via introspection.

options {
  server = providerPk;
  exit = 144;
}

contract StablePosition(
  pubkey userPk,
  pubkey providerPk,
  bytes32 priceAssetId,      // PriceBeacon reference
  int targetUSD,
  int entryPrice,
  int totalCollateral
) {
  // User settles - include beacon as input[1]
  function settle(signature userSig) {
    require(checkSig(userSig, userPk), "invalid user signature");

    // Read price from beacon input
    int currentPrice = tx.inputs[1].assets.lookup(priceAssetId);
    require(currentPrice > 0, "invalid price");

    int userPayout = targetUSD * 100000000 / currentPrice;
    require(userPayout <= totalCollateral, "insufficient collateral");

    require(tx.outputs[0].value >= userPayout, "payout too low");
    require(tx.outputs[0].scriptPubKey == new P2TR(userPk), "not user");

    int providerPayout = totalCollateral - userPayout;
    if (providerPayout > 546) {
      require(tx.outputs[1].value >= providerPayout, "provider payout low");
      require(tx.outputs[1].scriptPubKey == new P2TR(providerPk), "not provider");
    }

    // Beacon must survive
    require(tx.outputs[2].assets.lookup(priceAssetId) >= currentPrice, "beacon died");
  }

  // Transfer to new owner
  function transfer(signature userSig, pubkey newUserPk) {
    require(checkSig(userSig, userPk), "invalid signature");
    require(
      tx.outputs[0].scriptPubKey == new StablePosition(
        newUserPk, providerPk, priceAssetId,
        targetUSD, entryPrice, totalCollateral
      ),
      "invalid transfer"
    );
    require(tx.outputs[0].value >= totalCollateral, "collateral lost");
  }

  // Provider liquidates if undercollateralized
  function liquidate(signature providerSig) {
    require(checkSig(providerSig, providerPk), "invalid signature");

    int currentPrice = tx.inputs[1].assets.lookup(priceAssetId);
    int userValueBTC = targetUSD * 100000000 / currentPrice;
    int required = userValueBTC * 120 / 100;
    require(totalCollateral < required, "not undercollateralized");

    require(tx.outputs[0].value >= totalCollateral, "claim all");
    require(tx.outputs[0].scriptPubKey == new P2TR(providerPk), "not provider");
    require(tx.outputs[1].assets.lookup(priceAssetId) >= currentPrice, "beacon died");
  }

  // Provider tops up collateral
  function topUp(signature providerSig, int additionalBTC) {
    require(checkSig(providerSig, providerPk), "invalid signature");
    require(additionalBTC > 0, "must add");

    int newCollateral = totalCollateral + additionalBTC;
    require(
      tx.outputs[0].scriptPubKey == new StablePosition(
        userPk, providerPk, priceAssetId,
        targetUSD, entryPrice, newCollateral
      ),
      "invalid top-up"
    );
    require(tx.outputs[0].value >= newCollateral, "insufficient");
  }
}`
        }
    }
};

// Single file examples
const examples = {
    bare: {
        name: 'BareVTXO',
        code: `// Contract configuration options
options {
  // Server key
  server = server;

  // Renewal timelock: 7 days (1008 blocks)
  renew = 1008;

  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract BareVTXO(
  pubkey user
) {
  // Single signature spend path
  // This will automatically be compiled into:
  // 1. Cooperative path: checkSig(user) && checkSig(server)
  // 2. Exit path: checkSig(user) && after 144 blocks
  function spend(signature userSig) {
    require(checkSig(userSig, user));
  }
}`
    },

    htlc: {
        name: 'HTLC',
        code: `// Hash Time-Locked Contract (HTLC)
options {
  server = server;
  exit = 144;
}

contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes32 hashLock,
  int timeout
) {
  // Receiver claims with preimage
  function claim(signature receiverSig, bytes32 preimage) {
    require(sha256(preimage) == hashLock);
    require(checkSig(receiverSig, receiver));
  }

  // Sender refunds after timeout
  function refund(signature senderSig) {
    require(tx.time >= timeout);
    require(checkSig(senderSig, sender));
  }
}`
    },

    multisig: {
        name: 'MultiSig',
        code: `// 2-of-3 MultiSig Vault
options {
  server = server;
  exit = 288;
}

contract MultiSigVault(
  pubkey owner1,
  pubkey owner2,
  pubkey owner3
) {
  // Spend requires 2 of 3 owner signatures
  function spend(signature sig1, signature sig2) {
    require(checkMultisig([sig1, sig2], [owner1, owner2, owner3]));
  }
}`
    },

    swap: {
        name: 'Non-Interactive Swap',
        code: `// Non-Interactive Swap Contract
// Allows users to exchange assets without requiring both parties to be online simultaneously.

options {
  server = serverPk;
  exit = 144;
}

contract NonInteractiveSwap(
  pubkey makerPk,
  bytes32 offerAssetId,
  int offerAmount,
  bytes32 wantAssetId,
  int wantAmount,
  int expirationTime
) {
  // Swap: Any taker can fulfill
  function swap(pubkey takerPk, signature takerSig) {
    require(checkSig(takerSig, takerPk), "invalid taker signature");

    // Output 0: maker receives wantAsset
    require(
      tx.outputs[0].assets.lookup(wantAssetId) >= wantAmount,
      "insufficient want asset for maker"
    );
    require(
      tx.outputs[0].scriptPubKey == new P2TR(makerPk),
      "output 0 not spendable by maker"
    );

    // Output 1: taker receives offerAsset
    require(
      tx.outputs[1].assets.lookup(offerAssetId) >= offerAmount,
      "insufficient offer asset for taker"
    );
    require(
      tx.outputs[1].scriptPubKey == new P2TR(takerPk),
      "output 1 not spendable by taker"
    );
  }

  // Cancel: Maker reclaims after expiration
  function cancel(signature makerSig) {
    require(tx.time >= expirationTime, "swap not expired");
    require(checkSig(makerSig, makerPk), "invalid maker signature");
  }
}`
    }
};

// Global state
let editor = null;
let wasmReady = false;
let currentProject = null;
let currentFile = null;
let openTabs = [];
let fileContents = {}; // Cache of file contents for each open file
let expandedFolders = new Set(); // Track which folders are expanded

// Initialize WASM module
async function initCompiler() {
    try {
        await initWasm();
        initPanicHook();
        wasmReady = true;

        const ver = version();
        document.getElementById('compiler-version').textContent = `v${ver}`;
        document.getElementById('footer-version').textContent = `v${ver}`;

        // Auto-compile on load
        doCompile();
    } catch (err) {
        console.error('Failed to initialize WASM:', err);
        showError('Failed to load compiler. Make sure the WASM module is built.');
    }
}

// Render file tree
function renderFileTree() {
    const container = document.getElementById('file-tree');
    let html = '';

    // Projects section
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
            html += `<div class="tree-item ${isActive ? 'active' : ''}" data-project="${id}" data-file="${fileName}">
                <i class="fas fa-file-code"></i>
                ${fileName}
            </div>`;
        }
        html += '</div>';
    }

    // Examples folder
    const examplesExpanded = expandedFolders.has('_examples');
    html += `<div class="tree-folder" data-folder="_examples">
        <i class="fas ${examplesExpanded ? 'fa-chevron-down' : 'fa-chevron-right'}"></i>
        <i class="fas fa-folder${examplesExpanded ? '-open' : ''}"></i>
        Examples
    </div>`;
    html += `<div class="tree-folder-content ${examplesExpanded ? 'expanded' : ''}" data-folder="_examples">`;
    for (const [id, example] of Object.entries(examples)) {
        const isActive = currentProject === null && currentFile === id;
        html += `<div class="tree-item ${isActive ? 'active' : ''}" data-example="${id}">
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
    });

    container.querySelectorAll('.tree-item[data-project]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.stopPropagation();
            selectProjectFile(item.dataset.project, item.dataset.file);
        });
    });

    container.querySelectorAll('.tree-item[data-example]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.stopPropagation();
            selectExample(item.dataset.example);
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
    doCompile();
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
    doCompile();
}

// Save current file content to cache
function saveCurrentFile() {
    if (!editor) return;

    let tabId;
    if (currentProject) {
        tabId = `${currentProject}:${currentFile}`;
    } else if (currentFile) {
        tabId = currentFile;
    }

    if (tabId) {
        fileContents[tabId] = editor.getValue();
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
    doCompile();
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
            selectExample('bare');
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
            value: examples.bare.code,
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

        // Compile on change (debounced)
        let compileTimeout = null;
        editor.onDidChangeModelContent(() => {
            clearTimeout(compileTimeout);
            compileTimeout = setTimeout(() => {
                doCompile();
            }, 500);
        });

        // Initialize WASM after editor is ready
        initCompiler();
    });
}

// Compile the source code
function doCompile() {
    if (!wasmReady || !editor) return;

    const source = editor.getValue();
    clearErrors();

    try {
        const result = compile(source);
        displayJson(result);
        displayAsm(result);
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
    return asm
        .split(' ')
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

// Show error
function showError(message) {
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
    // Expand Examples folder by default
    expandedFolders.add('_examples');

    // Render file tree
    renderFileTree();

    // Set initial file state
    currentFile = 'bare';
    openTabs.push({ id: 'bare', project: null, file: 'bare', name: 'BareVTXO.ark' });
    fileContents['bare'] = examples.bare.code;
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

    // Copy button
    document.getElementById('copy-btn').addEventListener('click', copyOutput);
});
