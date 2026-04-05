// Arkade Language Definition for Monaco Editor

// Monarch tokenizer definition (for setMonarchTokensProvider)
const arkadeMonarch = {
    defaultToken: 'invalid',

    keywords: [
        'contract', 'function', 'options', 'require', 'if', 'else',
        'for', 'in', 'let', 'internal', 'new'
    ],

    typeKeywords: [
        'pubkey', 'signature', 'bytes32', 'bytes20', 'bytes',
        'asset', 'int', 'bool'
    ],

    builtinFunctions: [
        'checkSig', 'checkMultisig', 'checkSigFromStack', 'checkSigFromStackVerify',
        'sha256', 'sha256Initialize', 'sha256Update', 'sha256Finalize',
        'neg64', 'le64ToScriptNum', 'le32ToLe64', 'ecMulScalarVerify', 'tweakVerify'
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
            [/\b(contract|function|options|require|if|else|for|in|let|internal|new)\b/, 'keyword'],

            // Types
            [/\b(pubkey|signature|bytes32|bytes20|bytes|asset|int|bool)\b/, 'type'],

            // Built-in functions
            [/\b(checkSig|checkMultisig|checkSigFromStack|checkSigFromStackVerify|sha256|sha256Initialize|sha256Update|sha256Finalize|neg64|le64ToScriptNum|le32ToLe64|ecMulScalarVerify|tweakVerify)\b/, 'predefined'],

            // Transaction/this keywords
            [/\b(tx|this)\b/, 'variable.predefined'],

            // P2TR constructor
            [/\bP2TR\b/, 'type'],

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
const arkadeCompletions = [
    // Keywords
    { label: 'contract', kind: 'Keyword', insertText: 'contract ${1:Name}(${2:params}) {\n\t$0\n}', insertTextRules: 4 },
    { label: 'function', kind: 'Keyword', insertText: 'function ${1:name}(${2:params}) {\n\t$0\n}', insertTextRules: 4 },
    { label: 'options', kind: 'Keyword', insertText: 'options {\n\tserver = ${1:server};\n\texit = ${2:144};\n}', insertTextRules: 4 },
    { label: 'require', kind: 'Keyword', insertText: 'require(${1:condition});', insertTextRules: 4 },
    { label: 'if', kind: 'Keyword', insertText: 'if (${1:condition}) {\n\t$0\n}', insertTextRules: 4 },
    { label: 'for', kind: 'Keyword', insertText: 'for (${1:i}, ${2:item}) in ${3:array} {\n\t$0\n}', insertTextRules: 4 },
    { label: 'let', kind: 'Keyword', insertText: 'let ${1:name} = ${2:value};', insertTextRules: 4 },
    { label: 'internal', kind: 'Keyword', insertText: 'internal' },

    // Types
    { label: 'pubkey', kind: 'TypeParameter', insertText: 'pubkey' },
    { label: 'signature', kind: 'TypeParameter', insertText: 'signature' },
    { label: 'bytes', kind: 'TypeParameter', insertText: 'bytes' },
    { label: 'bytes20', kind: 'TypeParameter', insertText: 'bytes20' },
    { label: 'bytes32', kind: 'TypeParameter', insertText: 'bytes32' },
    { label: 'int', kind: 'TypeParameter', insertText: 'int' },
    { label: 'bool', kind: 'TypeParameter', insertText: 'bool' },
    { label: 'asset', kind: 'TypeParameter', insertText: 'asset' },

    // Functions
    { label: 'checkSig', kind: 'Function', insertText: 'checkSig(${1:sig}, ${2:pubkey})', insertTextRules: 4, detail: 'Verify signature against pubkey' },
    { label: 'checkMultisig', kind: 'Function', insertText: 'checkMultisig([${1:sigs}], [${2:pubkeys}])', insertTextRules: 4, detail: 'Verify multiple signatures' },
    { label: 'checkSigFromStack', kind: 'Function', insertText: 'checkSigFromStack(${1:sig}, ${2:pubkey}, ${3:msg})', insertTextRules: 4, detail: 'Verify signature from stack' },
    { label: 'sha256', kind: 'Function', insertText: 'sha256(${1:data})', insertTextRules: 4, detail: 'SHA256 hash' },

    // Transaction introspection
    { label: 'tx.time', kind: 'Property', insertText: 'tx.time', detail: 'Transaction locktime' },
    { label: 'tx.inputs', kind: 'Property', insertText: 'tx.inputs[${1:i}]', insertTextRules: 4, detail: 'Transaction inputs' },
    { label: 'tx.outputs', kind: 'Property', insertText: 'tx.outputs[${1:o}]', insertTextRules: 4, detail: 'Transaction outputs' },
    { label: 'tx.input.current', kind: 'Property', insertText: 'tx.input.current', detail: 'Current input' },

    // P2TR
    { label: 'P2TR', kind: 'Constructor', insertText: 'new P2TR(${1:internalKey})', insertTextRules: 4, detail: 'Create P2TR scriptPubKey' },
];

// Export all parts
window.arkadeMonarch = arkadeMonarch;
window.arkadeLanguageConfig = arkadeLanguageConfig;
window.arkadeTheme = arkadeTheme;
window.arkadeCompletions = arkadeCompletions;
