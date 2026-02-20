# HTLC
#
#

# Function: together (cooperative)
<sender>
OP_CHECKSIG
<receiver>
OP_CHECKSIGADD
OP_2
OP_NUMEQUAL
<SERVER_KEY>
<serverSig>
OP_CHECKSIG

# Function: together (exit)
<sender>
OP_CHECKSIG
<receiver>
OP_CHECKSIGADD
OP_2
OP_NUMEQUAL
144
OP_CHECKSEQUENCEVERIFY
OP_DROP

# Function: refund (cooperative)
<sender>
<senderSig>
OP_CHECKSIG
<refundTime>
OP_CHECKLOCKTIMEVERIFY
OP_DROP
<SERVER_KEY>
<serverSig>
OP_CHECKSIG

# Function: refund (exit)
<sender>
<senderSig>
OP_CHECKSIG
<refundTime>
OP_CHECKLOCKTIMEVERIFY
OP_DROP
144
OP_CHECKSEQUENCEVERIFY
OP_DROP

# Function: claim (cooperative)
<receiver>
<receiverSig>
OP_CHECKSIG
<preimage>
OP_SHA256
<hash>
OP_EQUAL
<SERVER_KEY>
<serverSig>
OP_CHECKSIG

# Function: claim (exit)
<receiver>
<receiverSig>
OP_CHECKSIG
<preimage>
OP_SHA256
<hash>
OP_EQUAL
144
OP_CHECKSEQUENCEVERIFY
OP_DROP

