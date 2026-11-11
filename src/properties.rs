//! Introspection properties. Each one is described once here; parsing, type
//! inference and code generation read these instead of matching names.

macro_rules! properties {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => ($text:literal, $ty:literal, $doc:literal)),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant),*
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            /// Source name, value type and documentation.
            pub(crate) fn describe(self) -> (&'static str, &'static str, &'static str) {
                match self {
                    $(Self::$variant => ($text, $ty, $doc)),*
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
        Version => ("version", "int", "Transaction version."),
        Locktime => ("locktime", "int", "Transaction nLockTime. Not a clock; use checkTime for time."),
        NumInputs => ("numInputs", "int", "Number of transaction inputs."),
        NumOutputs => ("numOutputs", "int", "Number of transaction outputs."),
        Weight => ("weight", "int", "Transaction weight."),
        Id => ("id", "bytes32", "Transaction id."),
    }
);

properties!(
    /// `tx.inputs[i].<property>`
    InputProperty {
        Value => ("value", "int", "Input value in satoshis."),
        WitnessVersion => ("witnessVersion", "int", "Witness version (0-16) of the input's script."),
        Sequence => ("sequence", "int", "Input nSequence."),
        Outpoint => ("outpoint", "Outpoint", "Outpoint the input spends: {txid, vout}."),
        ArkadeScriptHash => ("arkadeScriptHash", "bytes32", "Hash of the input's Arkade script."),
        ArkadeWitnessHash => ("arkadeWitnessHash", "bytes32", "Hash of the input's Arkade witness."),
        Script => ("script", "ScriptPubKey", "The input's witness program and version, {program, version}, from one inspection."),
    }
);

properties!(
    /// `tx.outputs[o].<property>`
    OutputProperty {
        Value => ("value", "int", "Output value in satoshis."),
        WitnessVersion => ("witnessVersion", "int", "Witness version (0-16) of the output's script."),
        Script => ("script", "ScriptPubKey", "The output's witness program and version, {program, version}, from one inspection."),
    }
);

properties!(
    /// `this.<property>`; `this.activeBytecode` is the current input's script struct.
    ThisProperty {
        ActiveInputIndex => ("activeInputIndex", "int", "Index of the input being spent."),
        Expiry => ("expiry", "int", "Unix expiry of the executing VTXO, in seconds. Fails the spend when unavailable."),
    }
);

properties!(
    /// `group.<property>` on an `AssetGroup`
    GroupProperty {
        NumInputs => ("numInputs", "int", "Number of the group's input records."),
        NumOutputs => ("numOutputs", "int", "Number of the group's output records."),
        SumInputs => ("sumInputs", "int", "Total amount of the group's inputs."),
        SumOutputs => ("sumOutputs", "int", "Total amount of the group's outputs."),
        Delta => ("delta", "int", "sumOutputs minus sumInputs: positive when minting, negative when burning."),
        HasControl => ("hasControl", "bool", "Whether the group has a control asset."),
        ControlAssetId => ("controlAssetId", "AssetId", "Id of the group's control asset. Fails the spend when there is none."),
        MetadataHash => ("metadataHash", "bytes32", "Hash of the group's metadata."),
        AssetId => ("assetId", "AssetId", "Id of the group's asset."),
        IsFresh => ("isFresh", "bool", "Whether the group issues a new asset."),
    }
);

properties!(
    /// `group.inputs[j].<property>`, `group.outputs[j].<property>`
    GroupIoProperty {
        Amount => ("amount", "int", "Record amount."),
        Type => ("type", "int", "1 for a local input, 2 for an intent input; always 1 for an output."),
        Index => ("index", "int", "An output's vout, a local input's vin, or the output an intent input references."),
        Txid => ("txid", "bytes32", "An intent input's source transaction. Fails the spend on a local input."),
    }
);

properties!(
    /// `tx.inputs[i].assets[j].<property>`, `tx.outputs[o].assets[j].<property>`
    AssetProperty {
        AssetId => ("assetId", "AssetId", "Asset id: {txid, gidx}."),
        Amount => ("amount", "int", "Asset amount."),
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
