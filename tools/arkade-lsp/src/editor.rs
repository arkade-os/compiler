//! Import links, semantic tokens, cost lenses and signature help, all from the cached analysis.

use arkade_compiler::symbols::{Definition, SymbolKind as Kind};
use lsp_types::{
    CodeLens, Command, DocumentLink, ParameterInformation, ParameterLabel, Position, SemanticToken,
    SemanticTokenModifier, SemanticTokenType, SemanticTokens, SemanticTokensLegend, SignatureHelp,
    SignatureInformation, Url,
};

use crate::project::{offset, range};
use crate::Server;

/// The token types semantic tokens index, in order.
pub(crate) const TOKEN_TYPES: [SemanticTokenType; 8] = [
    SemanticTokenType::NAMESPACE,
    SemanticTokenType::CLASS,
    SemanticTokenType::STRUCT,
    SemanticTokenType::FUNCTION,
    SemanticTokenType::PARAMETER,
    SemanticTokenType::VARIABLE,
    SemanticTokenType::PROPERTY,
    SemanticTokenType::MACRO,
];

pub(crate) fn legend() -> SemanticTokensLegend {
    SemanticTokensLegend {
        token_types: TOKEN_TYPES.to_vec(),
        token_modifiers: vec![
            SemanticTokenModifier::DECLARATION,
            SemanticTokenModifier::READONLY,
        ],
    }
}

/// The index into `TOKEN_TYPES` of a symbol of `kind`, and whether it is read-only.
fn token(kind: Kind) -> (u32, bool) {
    match kind {
        Kind::Library => (0, false),
        Kind::Contract => (1, false),
        Kind::Struct => (2, false),
        Kind::Function => (3, false),
        Kind::Parameter => (4, false),
        Kind::Variable => (5, false),
        Kind::Constant => (5, true),
        Kind::Field => (6, false),
        Kind::Tapscript => (7, false),
    }
}

impl Server {
    /// Each import of the document, linked to the file it names.
    pub(crate) fn document_links(&self, uri: &Url) -> Vec<DocumentLink> {
        let Some(project) = self.project(uri) else {
            return Vec::new();
        };
        let imports = project.imports().into_iter();
        let links = imports.filter_map(|(file, range)| {
            let target = project.uri(&file)?;
            Some(DocumentLink {
                range,
                target: Some(target),
                tooltip: Some(file),
                data: None,
            })
        });
        links.collect()
    }

    /// The document's names, each with its symbol's kind, its definitions marked as such.
    /// O(the symbols of the document's closure).
    pub(crate) fn semantic_tokens(&self, uri: &Url) -> SemanticTokens {
        let Some(project) = self.project(uri) else {
            return SemanticTokens::default();
        };
        let analysis = self.analyze(&project);
        let symbols = analysis.symbols();
        let source = project.source();
        let own = symbols
            .definitions()
            .iter()
            .filter(|d| d.file == project.entry);
        let mut names: Vec<_> = own.map(|d| (d.span, d.kind, true)).collect();
        let uses = symbols
            .references()
            .iter()
            .filter(|r| r.file == project.entry);
        names.extend(uses.map(|r| (r.span, symbols.definitions()[r.definition].kind, false)));
        names.sort_by_key(|(span, _, _)| (span.start, span.end));
        names.dedup_by_key(|(span, _, _)| span.start);

        let mut data = Vec::new();
        let (mut line, mut character, mut end) = (0, 0, 0);
        for (span, kind, declaration) in names {
            let at = range(source, span);
            if span.start < end || at.start.line != at.end.line || span.start == span.end {
                continue;
            }
            let (token_type, readonly) = token(kind);
            let delta_line = at.start.line - line;
            let delta_start = match delta_line {
                0 => at.start.character - character,
                _ => at.start.character,
            };
            data.push(SemanticToken {
                delta_line,
                delta_start,
                length: at.end.character - at.start.character,
                token_type,
                token_modifiers_bitset: u32::from(declaration) | (u32::from(readonly) << 1),
            });
            (line, character, end) = (at.start.line, at.start.character, span.end);
        }
        SemanticTokens {
            result_id: None,
            data,
        }
    }

    /// Over each covenant function, the script size and stack peak its compiled covenant uses.
    pub(crate) fn code_lenses(&self, uri: &Url) -> Vec<CodeLens> {
        let Some(project) = self.project(uri) else {
            return Vec::new();
        };
        let analysis = self.analyze(&project);
        let Some(artifact) = analysis.artifact() else {
            return Vec::new();
        };
        let functions: Vec<&Definition> = (analysis.symbols().definitions().iter())
            .filter(|d| d.kind == Kind::Function && d.file == project.entry)
            .collect();
        let lenses = artifact.functions.iter().filter_map(|group| {
            let covenant = group.arkade.as_ref()?;
            let function = functions.iter().find(|d| d.name == group.name)?;
            let cost = |name: &str| {
                covenant
                    .costs
                    .iter()
                    .find(|c| c.name == name)
                    .map(|c| c.used)
            };
            let title = format!(
                "{} B script · {} stack items · {} ops",
                cost("script bytes (min)")?,
                cost("stack items (peak)")?,
                covenant.asm.len()
            );
            Some(CodeLens {
                range: range(project.source(), function.span),
                command: Some(Command::new(title, String::new(), None)),
                data: None,
            })
        });
        lenses.collect()
    }

    /// The signature of the call around the cursor, a built-in's or one of the contract's or an
    /// imported library's functions, with the argument the cursor is in.
    pub(crate) fn signature_help(&self, (uri, cursor): (Url, Position)) -> Option<SignatureHelp> {
        let project = self.project(&uri)?;
        let at = offset(project.source(), cursor)?;
        let (name, active) = call_at(&project.source()[..at])?;
        let (label, parameters) = match arkade_compiler::signature(name) {
            Some(signature) => {
                let inner = signature.split_once('(')?.1.trim_end_matches(')');
                let parameters = inner.split(", ").filter(|p| !p.is_empty());
                (signature.clone(), parameters.map(str::to_string).collect())
            }
            None => {
                let (analysis, _) = self.typing(&project, cursor)?;
                let contract = analysis.contract()?;
                let function = contract.functions.iter().find(|f| f.name == name)?;
                let parameters: Vec<String> = (function.parameters.iter())
                    .map(|p| format!("{} {}", p.param_type, p.name))
                    .collect();
                (format!("{name}({})", parameters.join(", ")), parameters)
            }
        };
        let parameters = parameters.into_iter().map(|p| ParameterInformation {
            label: ParameterLabel::Simple(p),
            documentation: None,
        });
        Some(SignatureHelp {
            signatures: vec![SignatureInformation {
                label,
                documentation: None,
                parameters: Some(parameters.collect()),
                active_parameter: Some(active),
            }],
            active_signature: Some(0),
            active_parameter: Some(active),
        })
    }
}

/// The name of the call whose arguments `before` ends inside, such as `Fees.calculate`, and the
/// index of the argument being written. O(`before`).
fn call_at(before: &str) -> Option<(&str, u32)> {
    let (mut depth, mut commas, mut quoted) = (0i32, 0, false);
    for (i, c) in before.char_indices().rev() {
        match c {
            '"' => quoted = !quoted,
            _ if quoted => {}
            ')' | ']' => depth += 1,
            '(' | '[' if depth > 0 => depth -= 1,
            '(' => {
                let name = before[..i].trim_end();
                let start = name
                    .trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                    .len();
                let name = &name[start..];
                return (!name.is_empty()).then_some((name, commas));
            }
            '[' | ';' | '{' | '}' => return None,
            ',' if depth == 0 => commas += 1,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_call_and_argument_at_the_cursor() {
        assert_eq!(
            super::call_at("require(checkSig(sig, "),
            Some(("checkSig", 1))
        );
        assert_eq!(
            super::call_at("x = Fees.calculate(f(a, b), "),
            Some(("Fees.calculate", 1))
        );
        assert_eq!(
            super::call_at("require(checkSig(\"a,(\", "),
            Some(("checkSig", 1))
        );
        assert_eq!(super::call_at("require(ok); x = 1"), None);
    }
}
