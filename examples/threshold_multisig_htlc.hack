# HTLC
#
#

# Function: together
## arkade covenant
<sender>
OP_CHECKSIG
<receiver>
OP_CHECKSIGADD
OP_2
OP_NUMEQUAL
## leaf: together
<SERVER_KEY>
OP_CHECKSIGVERIFY
<EMULATOR_KEY:together>
OP_CHECKSIG

# Function: refund
## arkade covenant
<sender>
<senderSig>
OP_CHECKSIG
<refundTime>
OP_CHECKLOCKTIMEVERIFY
OP_DROP
## leaf: refund
<SERVER_KEY>
OP_CHECKSIGVERIFY
<EMULATOR_KEY:refund>
OP_CHECKSIG

# Function: claim
## arkade covenant
<receiver>
<receiverSig>
OP_CHECKSIG
<preimage>
OP_SHA256
<hash>
OP_EQUAL
## leaf: claim
<SERVER_KEY>
OP_CHECKSIGVERIFY
<EMULATOR_KEY:claim>
OP_CHECKSIG

# Function: unilateral
## leaf: unilateral
<exit>
OP_CHECKSEQUENCEVERIFY
OP_DROP
<sender>
OP_CHECKSIG

