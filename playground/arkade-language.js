// Arkade Language Definition for Monaco Editor

// Monarch tokenizer definition (for setMonarchTokensProvider)
const arkadeMonarch = {
    defaultToken: 'invalid',

    keywords: [
        'contract', 'library', 'struct', 'function', 'tapscript', 'require', 'if', 'else',
        'for', 'in', 'let', 'private', 'public', 'static', 'const', 'return', 'new', 'import'
    ],

    typeKeywords: [
        'pubkey', 'signature', 'bytes32', 'bytes20', 'bytes',
        'asset', 'int', 'bool'
    ],

    builtinFunctions: [
        'checkSig', 'checkMultisig', 'checkSigFromStack', 'checkSigFromStackVerify',
        'sha256', 'sha256Initialize', 'sha256Update', 'sha256Finalize',
        'digest', 'sighash', 'modExp', 'reverseBytes',
        'ecAdd', 'ecMul', 'ecPairing', 'ecMulScalarVerify', 'tweakVerify',
        'older', 'after', 'tweak'
    ],

    operators: [
        '>=', '<=', '==', '!=', '>', '<', '+', '-', '*', '/', '='
    ],

    tokenizer: {
        root: [
            // Comments
            [/\/\/.*$/, 'comment'],
            [/\/\*/, 'comment', '@comment'],

            // Whitespace
            [/\s+/, 'white'],

            // Keywords
            [/\b(contract|library|struct|function|tapscript|require|if|else|for|in|let|private|public|static|const|return|new|import)\b/, 'keyword'],

            // Types
            [/\b(pubkey|signature|bytes32|bytes20|bytes|asset|int|bool)\b/, 'type'],

            // Built-in functions
            [/\b(checkSig|checkMultisig|checkSigFromStack|checkSigFromStackVerify|sha256|sha256Initialize|sha256Update|sha256Finalize|digest|sighash|modExp|reverseBytes|ecAdd|ecMul|ecPairing|ecMulScalarVerify|tweakVerify|older|after|tweak)\b/, 'predefined'],

            // Transaction/this keywords
            [/\b(tx|this)\b/, 'variable.predefined'],

            // Numbers
            [/\b\d+\b/, 'number'],

            // Strings
            [/"[^"]*"/, 'string'],

            // Operators
            [/[>=<!=]+/, 'operator'],
            [/[+\-*/]/, 'operator'],

            // Delimiters
            [/[{}()\[\];,.]/, 'delimiter'],

            // Identifiers
            [/[a-zA-Z_]\w*/, 'identifier'],
        ],

        comment: [
            [/[^/*]+/, 'comment'],
            [/\*\//, 'comment', '@pop'],
            [/[/*]/, 'comment']
        ]
    }
};

// Language configuration (for setLanguageConfiguration)
const arkadeLanguageConfig = {
    comments: {
        lineComment: '//',
        blockComment: ['/*', '*/']
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

// Completions
const S = (label, kind, insertText, detail) => ({ label, kind, insertText, detail, snippet: insertText.includes('$') });
const prop = (label, detail) => S(label, 'Property', label, detail);
const method = (label, args, detail) => S(label, 'Method', `${label}(${args})`, detail);
const assetIdArgs = '${1:assetTxid}, ${2:assetGidx}';
const inputProps = [
    prop('value', 'Input value (sats)'),
    prop('scriptPubKey', 'Input scriptPubKey'),
    prop('sequence', 'Input nSequence'),
    prop('outpoint', 'Input outpoint'),
    prop('arkadeScriptHash', 'Hash of the input\'s Arkade script'),
    prop('arkadeWitnessHash', 'Hash of the input\'s Arkade witness'),
];
const groupProps = ['numInputs', 'numOutputs', 'sumInputs', 'sumOutputs', 'delta', 'hasControl', 'metadataHash', 'assetId', 'isFresh']
    .map(name => prop(name, 'Asset group property'));

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
    ...['pubkey', 'signature', 'bytes', 'bytes20', 'bytes32', 'int', 'bool', 'asset'].map(t => S(t, 'TypeParameter', t)),

    // Implicit bindings
    S('tx', 'Variable', 'tx', 'Spending transaction'),
    S('this', 'Variable', 'this', 'Current contract'),
    S('server', 'Variable', 'server', 'Arkade server key'),
    S('emulator', 'Variable', 'emulator', 'Arkade emulator key'),

    // Functions
    S('checkSig', 'Function', 'checkSig(${1:sig}, ${2:pubkey})', 'Verify signature against pubkey'),
    S('checkMultisig', 'Function', 'checkMultisig([${1:keys}], [${2:sigs}], ${3:threshold})', 'Verify multiple signatures'),
    S('checkSigFromStack', 'Function', 'checkSigFromStack(${1:sig}, ${2:pubkey}, ${3:msg})', 'Verify signature over a message'),
    S('checkSigFromStackVerify', 'Function', 'checkSigFromStackVerify(${1:sig}, ${2:pubkey}, ${3:msg})', 'Verify signature over a message or fail'),
    S('checkTime', 'Function', 'checkTime(${1:time})', 'Require the transaction time to have reached a value'),
    S('older', 'Function', 'older(${1:delay})', 'Relative CSV timelock'),
    S('after', 'Function', 'after(${1:locktime})', 'Absolute CLTV timelock'),
    S('tweak', 'Function', 'tweak(${1:emulator}, ${2:functionName})', 'Tweaked emulator key'),
    S('sha256', 'Function', 'sha256(${1:data})', 'SHA256 hash'),
    S('hash256', 'Function', 'hash256(${1:data}) == ${2:hash}', 'Double SHA256 comparison'),
    S('hash160', 'Function', 'hash160(${1:data}) == ${2:hash}', 'HASH160 comparison'),
    S('ripemd160', 'Function', 'ripemd160(${1:data}) == ${2:hash}', 'RIPEMD160 comparison'),
    S('sha256Initialize', 'Function', 'sha256Initialize(${1:data})', 'Start a streaming SHA256'),
    S('sha256Update', 'Function', 'sha256Update(${1:ctx}, ${2:chunk})', 'Update a streaming SHA256'),
    S('sha256Finalize', 'Function', 'sha256Finalize(${1:ctx}, ${2:lastChunk})', 'Finish a streaming SHA256'),
    S('digest', 'Function', 'digest(${1:data}, ${2:ctx})', 'Digest'),
    S('sighash', 'Function', 'sighash(${1:type})', 'Transaction sighash'),
    S('modExp', 'Function', 'modExp(${1:base}, ${2:exponent}, ${3:modulus})', 'Modular exponentiation'),
    S('ecAdd', 'Function', 'ecAdd(${1:a}, ${2:b}, ${3:c}, ${4:d}, ${5:e})', 'EC point addition'),
    S('ecMul', 'Function', 'ecMul(${1:a}, ${2:b}, ${3:c}, ${4:d})', 'EC scalar multiplication'),
    S('ecPairing', 'Function', 'ecPairing(${1:a}, ${2:b}, ${3:c}, ${4:d}, ${5:e}, ${6:f}, ${7:g})', 'EC pairing check'),
    S('ecMulScalarVerify', 'Function', 'ecMulScalarVerify(${1:k}, ${2:P}, ${3:Q})', 'Verify Q = k·P'),
    S('tweakVerify', 'Function', 'tweakVerify(${1:P}, ${2:k}, ${3:Q})', 'Verify Q = P + k·G'),
    S('substr', 'Function', 'substr(${1:data}, ${2:offset}, ${3:size})', 'Byte slice'),
    S('cat', 'Function', 'cat(${1:a}, ${2:b})', 'Byte concatenation'),
    S('bin2num', 'Function', 'bin2num(${1:bytes})', 'Bytes to number'),
    S('num2bin', 'Function', 'num2bin(${1:num}, ${2:size})', 'Number to fixed-width bytes'),
    S('reverseBytes', 'Function', 'reverseBytes(${1:bytes})', 'Reverse byte order'),
    S('size', 'Function', 'size(${1:bytes})', 'Byte length'),
];

// Members offered after `<path>.`, keyed by the path with indexes collapsed to `[]`.
const arkadeMembers = {
    'tx': [
        prop('time', 'Transaction time'),
        prop('version', 'Transaction version'),
        prop('locktime', 'Transaction locktime'),
        prop('numInputs', 'Number of inputs'),
        prop('numOutputs', 'Number of outputs'),
        prop('weight', 'Transaction weight'),
        prop('id', 'Transaction id'),
        S('inputs', 'Property', 'inputs[${1:i}]', 'Transaction inputs'),
        S('outputs', 'Property', 'outputs[${1:o}]', 'Transaction outputs'),
        prop('input', 'Current input (tx.input.current)'),
        prop('assetGroups', 'Asset groups'),
        prop('intent', 'Intent fields'),
        method('packet', '${1:packetType}', 'Extension packet bytes of this transaction'),
    ],
    'tx.input': [prop('current', 'Input being spent')],
    'tx.input.current': inputProps,
    'tx.inputs[]': [...inputProps, prop('assets', 'Input assets'), method('packet', '${1:packetType}', 'Extension packet of the previous Arkade transaction')],
    'tx.outputs[]': [prop('value', 'Output value (sats)'), prop('scriptPubKey', 'Output scriptPubKey'), prop('assets', 'Output assets')],
    'tx.inputs[].assets': [prop('length', 'Number of assets'), method('lookup', assetIdArgs, 'Amount of an asset'), method('has', assetIdArgs, 'Whether an asset is present')],
    'tx.inputs[].assets[]': [prop('assetId', 'Asset id'), prop('amount', 'Asset amount')],
    'tx.assetGroups': [method('find', assetIdArgs, 'Asset group by id'), method('has', assetIdArgs, 'Whether an asset group exists'), prop('length', 'Number of asset groups')],
    'tx.assetGroups[]': groupProps,
    'tx.intent': [method('field', '"${1:name}"', 'Intent field bytes'), method('has', '"${1:name}"', 'Whether an intent field is present')],
    'this': [
        prop('activeInputIndex', 'Index of the input being spent'),
        prop('activeBytecode', 'Script being executed'),
        prop('expiry', 'Contract expiry'),
        method('tunnel', '${1:contract}', 'Carry the contract into an output'),
    ],
};
arkadeMembers['tx.outputs[].assets'] = arkadeMembers['tx.inputs[].assets'];
arkadeMembers['tx.outputs[].assets[]'] = arkadeMembers['tx.inputs[].assets[]'];

const notTypes = new Set(['return', 'else', 'new', 'in', 'let', 'const', 'import', 'function', 'contract', 'library', 'struct', 'tapscript']);

// ponytail: regex scan of the whole file, not a parse — ignores scopes and imported files; switch to the WASM parser if that becomes misleading.
function arkadeDocumentSymbols(text) {
    const code = text.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    const structs = {}, vars = {}, items = [];
    for (const [, name, body] of code.matchAll(/\bstruct\s+([A-Za-z]\w*)\s*\{([^}]*)\}/g)) {
        structs[name] = [...body.matchAll(/([A-Za-z]\w*(?:\[[^\]]*\])?)\s+([A-Za-z]\w*)\s*;/g)].map(([, type, field]) => prop(field, type));
        items.push(S(name, 'Struct', name, 'struct'));
    }
    for (const [, kind, name] of code.matchAll(/\b(contract|library)\s+([A-Za-z]\w*)/g)) items.push(S(name, 'Class', name, kind));
    for (const [, name] of code.matchAll(/\bfunction\s+([A-Za-z]\w*)/g)) items.push(S(name, 'Function', `${name}($1)`, 'function'));
    for (const [, type, dims, name] of code.matchAll(/\b([A-Za-z]\w*)(\[[^\]]*\])?\s+([A-Za-z]\w*)\s*(?=[,);=])/g)) {
        if (!notTypes.has(type)) vars[name] = type + (dims || '');
    }
    for (const [, name, value] of code.matchAll(/\blet\s+([A-Za-z]\w*)\s*=\s*([^;]*)/g)) {
        vars[name] = /^tx\s*\.\s*assetGroups\s*(\.\s*find|\[)/.test(value) ? 'assetGroup' : 'let';
    }
    for (const [, index, item] of code.matchAll(/\bfor\s*\(\s*([A-Za-z]\w*)\s*,\s*([A-Za-z]\w*)\s*\)/g)) {
        vars[index] = 'int';
        vars[item] = 'item';
    }
    for (const [name, type] of Object.entries(vars)) items.push(S(name, 'Variable', name, type));
    return { items, structs, vars };
}

// Completions for the cursor position: `before` is the line up to the start of the word being typed.
function arkadeComplete(before, text) {
    const chain = before.replace(/\[[^\][]*\]/g, '[]').match(/([A-Za-z]\w*(?:\[\])*(?:\s*\.\s*[A-Za-z]\w*(?:\[\])*)*)\s*\.\s*$/);
    const symbols = arkadeDocumentSymbols(text);
    if (!chain) {
        const seen = new Set(arkadeCompletions.map(item => item.label));
        return [...arkadeCompletions, ...symbols.items.filter(item => !seen.has(item.label) && seen.add(item.label))];
    }
    const path = chain[1].replace(/\s+/g, '');
    if (arkadeMembers[path]) return arkadeMembers[path];
    const [, name, indexed] = path.match(/^(\w+)(\[\])?$/) || [];
    const type = symbols.vars[name] || '';
    if (type === 'assetGroup' && !indexed) return [...groupProps, method('controlIs', assetIdArgs, 'Whether the control asset matches')];
    if (type.endsWith(']') && !indexed) return [prop('length', 'Array length')];
    return symbols.structs[type.replace(/\[.*$/, '')] || [];
}

// Export all parts
window.arkadeMonarch = arkadeMonarch;
window.arkadeLanguageConfig = arkadeLanguageConfig;
window.arkadeTheme = arkadeTheme;
window.arkadeComplete = arkadeComplete;
