// Arkade Language Definition for Monaco Editor

// Language configuration (for setLanguageConfiguration)
const arkadeLanguageConfig = {
    comments: {
        lineComment: '//'
    },
    brackets: [
        ['{', '}'],
        ['[', ']'],
        ['(', ')']
    ],
    autoClosingPairs: [
        { open: '{', close: '}' },
        { open: '[', close: ']' },
        { open: '(', close: ')' },
        { open: '"', close: '"' }
    ],
    surroundingPairs: [
        { open: '{', close: '}' },
        { open: '[', close: ']' },
        { open: '(', close: ')' },
        { open: '"', close: '"' }
    ]
};

// Theme definition
const arkadeTheme = {
    base: 'vs-dark',
    inherit: true,
    rules: [
        { token: 'comment', foreground: '6A9955' },
        { token: 'keyword', foreground: 'C586C0' },
        { token: 'type', foreground: '4EC9B0' },
        { token: 'predefined', foreground: 'DCDCAA' },
        { token: 'variable.predefined', foreground: '9CDCFE' },
        { token: 'number', foreground: 'B5CEA8' },
        { token: 'string', foreground: 'CE9178' },
        { token: 'operator', foreground: 'D4D4D4' },
        { token: 'delimiter', foreground: 'D4D4D4' },
        { token: 'identifier', foreground: '9CDCFE' }
    ],
    colors: {
        'editor.background': '#1e1e1e',
        'editor.foreground': '#d4d4d4',
        'editorLineNumber.foreground': '#858585',
        'editorCursor.foreground': '#aeafad',
        'editor.selectionBackground': '#264f78',
        'editor.inactiveSelectionBackground': '#3a3d41'
    }
};

// Completions; builtin functions and members come from builtins.json through arkadeUseDocs.
const S = (label, kind, insertText, detail, documentation) => ({ label, kind, insertText, detail, documentation, snippet: insertText.includes('$') });
const prop = (label, detail) => S(label, 'Property', label, detail);

const arkadeCompletions = [
    // Keywords
    S('contract', 'Keyword', 'contract ${1:Name}(${2:params}) {\n\t$0\n}'),
    S('library', 'Keyword', 'library ${1:Name} {\n\t$0\n}'),
    S('struct', 'Keyword', 'struct ${1:Name} {\n\t${2:int} ${3:field};\n}'),
    S('function', 'Keyword', 'function ${1:name}(${2:params}) {\n\t$0\n}'),
    S('require', 'Keyword', 'require(${1:condition}, "${2:message}");'),
    S('tapscript', 'Keyword', 'tapscript {\n\t$0\n}', 'Tapscript function body'),
    S('if', 'Keyword', 'if (${1:condition}) {\n\t$0\n}'),
    S('else', 'Keyword', 'else {\n\t$0\n}'),
    S('for', 'Keyword', 'for (${1:i}, ${2:item}) in ${3:array} {\n\t$0\n}'),
    S('let', 'Keyword', 'let ${1:name} = ${2:value};'),
    S('private', 'Keyword', 'private function ${1:name}(${2:params}) ${3:bool} {\n\treturn ${4:value};\n}'),
    S('static', 'Keyword', 'static function ${1:name}(${2:params}) ${3:int} {\n\treturn ${4:value};\n}'),
    S('const', 'Keyword', 'const ${1:int} ${2:NAME} = ${3:0};'),
    S('public', 'Keyword', 'public'),
    S('return', 'Keyword', 'return ${1:value};'),
    S('new', 'Keyword', 'new ${1:Contract}(${2:args})'),
    S('import', 'Keyword', 'import "${1:./contract.ark}";', 'Import structs, a contract, or a library from a relative file'),
    S('pragma', 'Keyword', 'pragma arkade ^${1:0.1.0};', 'Compiler version constraint'),
    S('true', 'Keyword', 'true'),
    S('false', 'Keyword', 'false'),

    // Types
    ...['pubkey', 'signature', 'bytes', 'bytes20', 'bytes32', 'int', 'bool', 'asset', 'AssetGroup'].map(t => S(t, 'TypeParameter', t)),

    // Implicit bindings
    S('tx', 'Variable', 'tx', 'Spending transaction'),
    S('this', 'Variable', 'this', 'Current contract'),
    S('server', 'Variable', 'server', 'Arkade server key'),
    S('emulator', 'Variable', 'emulator', 'Arkade emulator key'),
    S('serverExitDelay', 'Variable', 'serverExitDelay', 'Arkade server unilateral exit delay'),
];

// Monarch tokenizer definition (for setMonarchTokensProvider); word lists come from the completions.
const completionLabels = kind => arkadeCompletions.filter(item => item.kind === kind).map(item => item.label);
const arkadeMonarch = {
    defaultToken: 'invalid',
    keywords: [...completionLabels('Keyword'), 'in'],
    typeKeywords: completionLabels('TypeParameter'),
    builtinFunctions: [],
    implicitBindings: completionLabels('Variable'),

    tokenizer: {
        root: [
            [/\/\/.*$/, 'comment'],
            [/\s+/, 'white'],
            [/(pragma)(\s+)(arkade)\b/, ['keyword', 'white', 'keyword']],
            [/\d+\.\d+\.\d+/, 'number'],
            [/0x[0-9a-fA-F]*/, 'number.hex'],
            [/\d+/, 'number'],
            [/"(?:[^"\\]|\\.)*"/, 'string'],
            [/[a-zA-Z]\w*/, {
                cases: {
                    '@keywords': 'keyword',
                    '@typeKeywords': 'type',
                    '@builtinFunctions': 'predefined',
                    '@implicitBindings': 'variable.predefined',
                    '@default': 'identifier'
                }
            }],
            [/[{}()\[\]]/, '@brackets'],
            [/[;,.:]/, 'delimiter'],
            [/[=<>!&|^~+\-*\/]+/, 'operator'],
        ]
    }
};

let docs = { functions: {}, members: {} };
let docLanguage = 'en';
let functionItems = [];
// Members offered after `<path>.`, keyed by the path with indexes collapsed to `[]`.
let arkadeMembers = {};
// Paths documented under another path, and the members the alias lacks.
const memberAliases = [['tx.input.current', 'tx.inputs[]', ['assets', 'packet']], ['tx.outputs[].assets', 'tx.inputs[].assets', []]];

const docText = doc => doc?.[docLanguage] ?? doc?.en ?? '';
// Snippet arguments: `bytes[] keys` becomes `[${1:keys}]`, and optional parameters are left out.
const call = (name, params) => `${name}(${params.filter(p => !p.endsWith('?')).map((p, i) => {
    const [type, arg] = p.split(' ');
    return type.endsWith(']') ? `[\${${i + 1}:${arg}}]` : `\${${i + 1}:${arg}}`;
}).join(', ')})`;
const declaration = (name, entry) => entry.params
    ? `function ${name}(${entry.params.join(', ')})${entry.result ? ` ${entry.result}` : ''}`
    : `${entry.type ? `${entry.type} ` : ''}${name}`;
const docItem = (kind, name, entry) => {
    const insert = entry.params ? call(name, entry.params) : entry.index ? `${name}[\${1:${entry.index}}]` : name;
    return S(name, kind, insert, declaration(name, entry).replace(/^function /, ''), docText(entry.doc));
};

// Use `json` (builtins.json) for completions, hover and declarations, in `language` where it has one.
function arkadeUseDocs(json, language = 'en') {
    docs = json;
    docLanguage = language;
    arkadeMonarch.builtinFunctions = Object.keys(docs.functions);
    // Tapscript-only timelocks are highlighted but not offered as completions.
    functionItems = Object.entries(docs.functions).filter(([, entry]) => !entry.tapscript)
        .map(([name, entry]) => docItem('Function', name, entry));
    arkadeMembers = {};
    for (const [key, entry] of Object.entries(docs.members)) {
        const dot = key.lastIndexOf('.');
        (arkadeMembers[key.slice(0, dot)] ??= []).push(docItem(entry.params ? 'Method' : 'Property', key.slice(dot + 1), entry));
    }
    for (const [alias, path, missing] of memberAliases) {
        arkadeMembers[alias] = arkadeMembers[path].filter(item => !missing.includes(item.label));
    }
}

const symbolKinds = { struct: 'Struct', contract: 'Class', library: 'Module', function: 'Function', constant: 'Constant', parameter: 'Variable', variable: 'Variable' };
const symbolItem = s => S(s.name, symbolKinds[s.kind], s.kind === 'function' ? `${s.name}($1)` : s.name, s.type ? `${s.kind}: ${s.type}` : s.kind);

// The path before a trailing `.` in `before`, with indexes collapsed to `[]`, or null.
function memberPath(before) {
    let flat = before;
    while (flat !== (flat = flat.replace(/\[[^\][]*\]/g, '<>')));
    const chain = flat.replaceAll('<>', '[]').match(/([A-Za-z]\w*(?:\[\])*(?:\s*\.\s*[A-Za-z]\w*(?:\[\])*)*)\s*\.\s*$/);
    return chain && chain[1].replace(/\s+/g, '');
}

// The documented path `path` stands for: an `AssetGroup` name stands for `tx.assetGroups[]`.
function documentedPath(path, visible) {
    const group = path.match(/^(\w+)(\.(?:inputs|outputs)\[\])?$/);
    if (visible.get(group?.[1])?.type === 'AssetGroup') return `tx.assetGroups[]${group[2] || ''}`;
    const alias = memberAliases.find(([from]) => path === from || path.startsWith(from + '.') || path.startsWith(from + '['));
    return alias ? alias[1] + path.slice(alias[0].length) : path;
}

// Completions for the cursor: `before` is the line up to the word being typed, and `table` the
// names the compiler sees at the cursor (or null before it is available).
function arkadeComplete(before, table) {
    const { symbols = [], structs = [], members = {} } = table || {};
    const visible = new Map(symbols.map(symbol => [symbol.name, symbol]));
    const path = memberPath(before);
    if (!path) {
        const builtins = [...arkadeCompletions, ...functionItems];
        const labels = new Set(builtins.map(item => item.label));
        return [...builtins, ...[...visible.values()].filter(s => !labels.has(s.name)).map(symbolItem)];
    }
    if (Object.hasOwn(arkadeMembers, path)) return arkadeMembers[path];
    if (Object.hasOwn(members, path)) return members[path].map(symbolItem);
    const documented = documentedPath(path, visible);
    if (Object.hasOwn(arkadeMembers, documented)) return arkadeMembers[documented];
    // The type the path names, such as `Signer` for `next.primary`, through struct fields.
    const struct = type => structs.find(s => s.name === type.replace(/\[.*$/, ''));
    let type = '';
    path.split('.').forEach((segment, index) => {
        const name = segment.replace(/\[\]$/, '');
        type = index === 0 ? visible.get(name)?.type || '' : struct(type)?.fields.find(f => f.name === name)?.type || '';
        if (segment.endsWith('[]')) type = type.endsWith(']') ? type.replace(/\[[^\]]*\]$/, '') : '';
    });
    if (type.endsWith(']')) return [prop('length', 'Array length')];
    return struct(type)?.fields.map(field => prop(field.name, field.type)) || [];
}

// The builtin `word` names after `before`: `{ key, declaration, doc }`, or null.
function arkadeDescribe(before, word, table) {
    const visible = new Map((table?.symbols || []).map(symbol => [symbol.name, symbol]));
    const path = memberPath(before);
    const [entries, key] = path ? [docs.members, `${documentedPath(path, visible)}.${word}`] : [docs.functions, word];
    if (!Object.hasOwn(entries, key)) return null;
    return { key, declaration: declaration(key, entries[key]), doc: docText(entries[key].doc) };
}

// The builtins as a read-only declaration file: its `text`, and the 1-based line of each key.
function arkadeDeclarations() {
    const lines = ['// Arkade builtin functions and members, generated from builtins.json.'];
    const at = {};
    for (const entries of [docs.functions, docs.members]) {
        for (const [key, entry] of Object.entries(entries)) {
            lines.push('', `// ${docText(entry.doc)}`);
            at[key] = lines.length + 1;
            lines.push(`${declaration(key, entry)};`);
        }
    }
    return { text: lines.join('\n'), lines: at };
}

// Export all parts
window.arkadeMonarch = arkadeMonarch;
window.arkadeLanguageConfig = arkadeLanguageConfig;
window.arkadeTheme = arkadeTheme;
window.arkadeComplete = arkadeComplete;
window.arkadeUseDocs = arkadeUseDocs;
window.arkadeDescribe = arkadeDescribe;
window.arkadeDeclarations = arkadeDeclarations;
