//! Introspection properties. Each one is described once here; parsing, type
//! inference and code generation read these instead of matching names.

macro_rules! properties {
    ($(#[$doc:meta])* $name:ident { $($variant:ident => ($text:literal, $ty:literal)),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant),*
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            /// Source name and value type.
            fn describe(self) -> (&'static str, &'static str) {
                match self {
                    $(Self::$variant => ($text, $ty)),*
                }
            }

            pub fn name(self) -> &'static str {
                self.describe().0
            }

            pub fn value_type(self) -> &'static str {
                self.describe().1
            }

            pub fn from_name(name: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|property| property.name() == name)
            }
        }
    };
}

properties!(
    /// `tx.<property>`
    TxProperty {
        Version => ("version", "int"),
        Locktime => ("locktime", "int"),
        NumInputs => ("numInputs", "int"),
        NumOutputs => ("numOutputs", "int"),
        Weight => ("weight", "int"),
        Id => ("id", "bytes32"),
    }
);

properties!(
    /// `tx.inputs[i].<property>`
    InputProperty {
        Value => ("value", "int"),
        ScriptPubKey => ("scriptPubKey", "bytes"),
        WitnessVersion => ("witnessVersion", "int"),
        Sequence => ("sequence", "int"),
        Outpoint => ("outpoint", "Outpoint"),
        ArkadeScriptHash => ("arkadeScriptHash", "bytes32"),
        ArkadeWitnessHash => ("arkadeWitnessHash", "bytes32"),
    }
);

properties!(
    /// `tx.outputs[o].<property>`
    OutputProperty {
        Value => ("value", "int"),
        ScriptPubKey => ("scriptPubKey", "bytes"),
        WitnessVersion => ("witnessVersion", "int"),
    }
);

properties!(
    /// `this.<property>`; `this.activeBytecode` is the current input's scriptPubKey.
    ThisProperty {
        ActiveInputIndex => ("activeInputIndex", "int"),
        Expiry => ("expiry", "int"),
    }
);

properties!(
    /// `group.<property>` on an `AssetGroup`
    GroupProperty {
        NumInputs => ("numInputs", "int"),
        NumOutputs => ("numOutputs", "int"),
        SumInputs => ("sumInputs", "int"),
        SumOutputs => ("sumOutputs", "int"),
        Delta => ("delta", "int"),
        HasControl => ("hasControl", "bool"),
        ControlAssetId => ("controlAssetId", "AssetId"),
        MetadataHash => ("metadataHash", "bytes32"),
        AssetId => ("assetId", "AssetId"),
        IsFresh => ("isFresh", "bool"),
    }
);

properties!(
    /// `group.inputs[j].<property>`, `group.outputs[j].<property>`. `index` is an
    /// output's vout, a local input's vin, or an intent input's referenced output.
    GroupIoProperty {
        Amount => ("amount", "int"),
        Type => ("type", "int"),
        Index => ("index", "int"),
    }
);

properties!(
    /// `tx.inputs[i].assets[j].<property>`, `tx.outputs[o].assets[j].<property>`
    AssetProperty {
        AssetId => ("assetId", "AssetId"),
        Amount => ("amount", "int"),
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    /// The quoted alternatives of a grammar rule.
    fn spelled(rule: &str) -> Vec<&'static str> {
        let grammar = include_str!("parser/grammar.pest");
        let start = grammar.find(&format!("{rule} = {{")).expect("rule exists");
        let body = &grammar[start..start + grammar[start..].find('}').unwrap()];
        body.split('"').skip(1).step_by(2).collect()
    }

    fn names<P: Copy>(all: &[P], name: fn(P) -> &'static str) -> Vec<&'static str> {
        all.iter().map(|&property| name(property)).collect()
    }

    #[test]
    fn the_grammar_spells_every_property() {
        assert_eq!(
            spelled("tx_introspection_property"),
            names(TxProperty::ALL, TxProperty::name)
        );
        assert_eq!(
            spelled("input_introspection_property"),
            names(InputProperty::ALL, InputProperty::name)
        );
        assert_eq!(
            spelled("output_introspection_property"),
            names(OutputProperty::ALL, OutputProperty::name)
        );
        assert_eq!(
            spelled("asset_group_property"),
            names(GroupProperty::ALL, GroupProperty::name)
        );
        assert_eq!(
            spelled("asset_group_io_property"),
            names(GroupIoProperty::ALL, GroupIoProperty::name)
        );
        assert_eq!(
            spelled("asset_at_property"),
            names(AssetProperty::ALL, AssetProperty::name)
        );
        let mut this = names(ThisProperty::ALL, ThisProperty::name);
        this.insert(1, "activeBytecode");
        assert_eq!(spelled("this_property"), this);
    }
}
