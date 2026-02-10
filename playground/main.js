// Arkade Playground - Main Application
// Import default export for WASM initialization, plus the exported functions
import initWasm, { compile, version, validate, init as initPanicHook } from './pkg/arkade_compiler.js';

// Example contracts
const examples = {
    bare: `// Contract configuration options
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
}`,

    htlc: `// Hash Time-Locked Contract (HTLC)
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
}`,

    multisig: `// 2-of-3 MultiSig Vault
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
};

// Global state
let editor = null;
let wasmReady = false;

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
            value: examples.bare,
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

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Initialize Monaco
    initMonaco();

    // Initialize resizer
    initResizer();

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    // Compile button
    document.getElementById('compile-btn').addEventListener('click', doCompile);

    // Copy button
    document.getElementById('copy-btn').addEventListener('click', copyOutput);

    // Example selector
    document.getElementById('example-select').addEventListener('change', (e) => {
        const example = e.target.value;
        if (example && examples[example] && editor) {
            editor.setValue(examples[example]);
            e.target.value = ''; // Reset selector
        }
    });
});
