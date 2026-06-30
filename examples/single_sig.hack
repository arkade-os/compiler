# SingleSig
#
#

# Function: spend
## arkade covenant
<user>
<userSig>
OP_CHECKSIG
## leaf: spend
<SERVER_KEY>
OP_CHECKSIGVERIFY
<EMULATOR_KEY:spend>
OP_CHECKSIG

# Function: unilateral
## leaf: unilateral
<exit>
OP_CHECKSEQUENCEVERIFY
OP_DROP
<user>
OP_CHECKSIG

