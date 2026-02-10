# NonInteractiveSwap
#
#

# Function: swap (cooperative)
<takerPk>
<takerSig>
OP_CHECKSIG
0
<wantAssetId_txid>
<wantAssetId_gidx>
OP_INSPECTOUTASSETLOOKUP
OP_DUP
OP_1NEGATE
OP_EQUAL
OP_NOT
OP_VERIFY
<wantAmount>
OP_GREATERTHANOREQUAL64
OP_VERIFY
0
OP_INSPECTOUTPUTSCRIPTPUBKEY
<new P2TR(makerPk)>
OP_EQUAL
1
<offerAssetId_txid>
<offerAssetId_gidx>
OP_INSPECTOUTASSETLOOKUP
OP_DUP
OP_1NEGATE
OP_EQUAL
OP_NOT
OP_VERIFY
<offerAmount>
OP_GREATERTHANOREQUAL64
OP_VERIFY
1
OP_INSPECTOUTPUTSCRIPTPUBKEY
<new P2TR(takerPk)>
OP_EQUAL
<SERVER_KEY>
<serverSig>
OP_CHECKSIG

# Function: swap (exit)
<makerPk>
<makerPkSig>
OP_CHECKSIGVERIFY
<takerPk>
<takerPkSig>
OP_CHECKSIG
144
OP_CHECKSEQUENCEVERIFY
OP_DROP

# Function: cancel (cooperative)
<expirationTime>
OP_CHECKLOCKTIMEVERIFY
OP_DROP
<makerPk>
<makerSig>
OP_CHECKSIG
<SERVER_KEY>
<serverSig>
OP_CHECKSIG

# Function: cancel (exit)
<expirationTime>
OP_CHECKLOCKTIMEVERIFY
OP_DROP
<makerPk>
<makerSig>
OP_CHECKSIG
144
OP_CHECKSEQUENCEVERIFY
OP_DROP

