use arkade_compiler::compile;
use arkade_compiler::opcodes::{
    OP_2, OP_3, OP_5, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKSIGADD, OP_DROP, OP_NUMEQUAL,
};
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

// Threshold multisig example source code
const THRESHOLD_MULTISIG_CODE: &str = r#"// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;

  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract ThresholdMultisig(
  pubkey signer,
  pubkey signer1,
  pubkey signer2,
  pubkey signer3,
  pubkey signer4,
  pubkey server
) {
  // n-of-n using no literal threshold
  function twoOfTwo(signature signerSig, signature signer1Sig) {
    require(checkMultisig([signer, signer1]));
  }

  // n-of-n using literal threshold
  function fiveOfFive(signature signerSig, signature signer1Sig, signature signer2Sig, signature signer3Sig, signature signer4Sig) {
    require(checkMultisig([signer, signer1, signer2, signer3, signer4], 5));
  }

  // m-of-n using literal threshold
  function threeOfFive(signature signerSig, signature signer1Sig, signature signer2Sig, signature signer3Sig, signature signer4Sig) {
    require(checkMultisig([signer, signer1, signer2, signer3, signer4], 3));
  }
}"#;

#[test]
fn test_threshold_multisig() {
    // Compile the contract
    let result = compile(THRESHOLD_MULTISIG_CODE);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());

    let output = result.unwrap();

    // Verify contract name
    assert_eq!(output.name, "ThresholdMultisig");

    // Verify parameters
    assert_eq!(output.parameters.len(), 6);
    assert_eq!(output.parameters[0].name, "signer");
    assert_eq!(output.parameters[0].param_type, "pubkey");
    assert_eq!(output.parameters[1].name, "signer1");
    assert_eq!(output.parameters[1].param_type, "pubkey");
    assert_eq!(output.parameters[2].name, "signer2");
    assert_eq!(output.parameters[2].param_type, "pubkey");
    assert_eq!(output.parameters[3].name, "signer3");
    assert_eq!(output.parameters[3].param_type, "pubkey");
    assert_eq!(output.parameters[4].name, "signer4");
    assert_eq!(output.parameters[4].param_type, "pubkey");
    assert_eq!(output.parameters[5].name, "server");
    assert_eq!(output.parameters[5].param_type, "pubkey");

    // Verify functions - now we have 6 functions (3 functions x 2 variants)
    assert_eq!(output.functions.len(), 6);

    // Verify twoOfTwo function with server variant
    let two_of_two_function = output
        .functions
        .iter()
        .find(|f| f.name == "twoOfTwo" && f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(two_of_two_function.function_inputs.len(), 2);

    // Check require types
    assert_eq!(two_of_two_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(two_of_two_function.asm.len(), 9);
    assert_eq!(two_of_two_function.asm[0], "<signer>");
    assert_eq!(two_of_two_function.asm[1], OP_CHECKSIG);
    assert_eq!(two_of_two_function.asm[2], "<signer1>");
    assert_eq!(two_of_two_function.asm[3], OP_CHECKSIGADD);
    assert_eq!(two_of_two_function.asm[4], OP_2);
    assert_eq!(two_of_two_function.asm[5], OP_NUMEQUAL);
    assert_eq!(two_of_two_function.asm[6], "<SERVER_KEY>");
    assert_eq!(two_of_two_function.asm[7], "<serverSig>");
    assert_eq!(two_of_two_function.asm[8], OP_CHECKSIG);

    // Verify fiveOfFive function with server variant
    let five_of_five_function = output
        .functions
        .iter()
        .find(|f| f.name == "fiveOfFive" && f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(five_of_five_function.function_inputs.len(), 5);

    // Check require types
    assert_eq!(five_of_five_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(five_of_five_function.asm.len(), 15);
    assert_eq!(five_of_five_function.asm[0], "<signer>");
    assert_eq!(five_of_five_function.asm[1], OP_CHECKSIG);
    assert_eq!(five_of_five_function.asm[2], "<signer1>");
    assert_eq!(five_of_five_function.asm[3], OP_CHECKSIGADD);
    assert_eq!(five_of_five_function.asm[4], "<signer2>");
    assert_eq!(five_of_five_function.asm[5], OP_CHECKSIGADD);
    assert_eq!(five_of_five_function.asm[6], "<signer3>");
    assert_eq!(five_of_five_function.asm[7], OP_CHECKSIGADD);
    assert_eq!(five_of_five_function.asm[8], "<signer4>");
    assert_eq!(five_of_five_function.asm[9], OP_CHECKSIGADD);
    assert_eq!(five_of_five_function.asm[10], OP_5);
    assert_eq!(five_of_five_function.asm[11], OP_NUMEQUAL);
    assert_eq!(five_of_five_function.asm[12], "<SERVER_KEY>");
    assert_eq!(five_of_five_function.asm[13], "<serverSig>");
    assert_eq!(five_of_five_function.asm[14], OP_CHECKSIG);

    // Verify threeOfFive function with server variant
    let three_of_five_function = output
        .functions
        .iter()
        .find(|f| f.name == "threeOfFive" && f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(three_of_five_function.function_inputs.len(), 5);

    // Check require types
    assert_eq!(three_of_five_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(three_of_five_function.asm.len(), 15);
    assert_eq!(three_of_five_function.asm[0], "<signer>");
    assert_eq!(three_of_five_function.asm[1], OP_CHECKSIG);
    assert_eq!(three_of_five_function.asm[2], "<signer1>");
    assert_eq!(three_of_five_function.asm[3], OP_CHECKSIGADD);
    assert_eq!(three_of_five_function.asm[4], "<signer2>");
    assert_eq!(three_of_five_function.asm[5], OP_CHECKSIGADD);
    assert_eq!(three_of_five_function.asm[6], "<signer3>");
    assert_eq!(three_of_five_function.asm[7], OP_CHECKSIGADD);
    assert_eq!(three_of_five_function.asm[8], "<signer4>");
    assert_eq!(three_of_five_function.asm[9], OP_CHECKSIGADD);
    assert_eq!(three_of_five_function.asm[10], OP_3);
    assert_eq!(three_of_five_function.asm[11], OP_NUMEQUAL);
    assert_eq!(three_of_five_function.asm[12], "<SERVER_KEY>");
    assert_eq!(three_of_five_function.asm[13], "<serverSig>");
    assert_eq!(three_of_five_function.asm[14], OP_CHECKSIG);

    // Verify twoOfTwo function with exit path
    let two_of_two_function = output
        .functions
        .iter()
        .find(|f| f.name == "twoOfTwo" && !f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(two_of_two_function.function_inputs.len(), 2);

    // Check require types
    assert_eq!(two_of_two_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(two_of_two_function.asm.len(), 9);
    assert_eq!(two_of_two_function.asm[0], "<signer>");
    assert_eq!(two_of_two_function.asm[1], OP_CHECKSIG);
    assert_eq!(two_of_two_function.asm[2], "<signer1>");
    assert_eq!(two_of_two_function.asm[3], OP_CHECKSIGADD);
    assert_eq!(two_of_two_function.asm[4], OP_2);
    assert_eq!(two_of_two_function.asm[5], OP_NUMEQUAL);
    assert_eq!(two_of_two_function.asm[6], "144");
    assert_eq!(two_of_two_function.asm[7], OP_CHECKSEQUENCEVERIFY);
    assert_eq!(two_of_two_function.asm[8], OP_DROP);

    // Verify fiveOfFive function with exit path
    let five_of_five_function = output
        .functions
        .iter()
        .find(|f| f.name == "fiveOfFive" && !f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(five_of_five_function.function_inputs.len(), 5);

    // Check require types
    assert_eq!(five_of_five_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(five_of_five_function.asm.len(), 15);
    assert_eq!(five_of_five_function.asm[0], "<signer>");
    assert_eq!(five_of_five_function.asm[1], OP_CHECKSIG);
    assert_eq!(five_of_five_function.asm[2], "<signer1>");
    assert_eq!(five_of_five_function.asm[3], OP_CHECKSIGADD);
    assert_eq!(five_of_five_function.asm[4], "<signer2>");
    assert_eq!(five_of_five_function.asm[5], OP_CHECKSIGADD);
    assert_eq!(five_of_five_function.asm[6], "<signer3>");
    assert_eq!(five_of_five_function.asm[7], OP_CHECKSIGADD);
    assert_eq!(five_of_five_function.asm[8], "<signer4>");
    assert_eq!(five_of_five_function.asm[9], OP_CHECKSIGADD);
    assert_eq!(five_of_five_function.asm[10], OP_5);
    assert_eq!(five_of_five_function.asm[11], OP_NUMEQUAL);
    assert_eq!(five_of_five_function.asm[12], "144");
    assert_eq!(five_of_five_function.asm[13], OP_CHECKSEQUENCEVERIFY);
    assert_eq!(five_of_five_function.asm[14], OP_DROP);

    // Verify threeOfFive function with exit path
    let three_of_five_function = output
        .functions
        .iter()
        .find(|f| f.name == "threeOfFive" && !f.server_variant)
        .unwrap();

    // Check function inputs
    assert_eq!(three_of_five_function.function_inputs.len(), 5);

    // Check require types
    assert_eq!(three_of_five_function.require[0].req_type, "multisig");

    // Check assembly instructions
    assert_eq!(three_of_five_function.asm.len(), 15);
    assert_eq!(three_of_five_function.asm[0], "<signer>");
    assert_eq!(three_of_five_function.asm[1], OP_CHECKSIG);
    assert_eq!(three_of_five_function.asm[2], "<signer1>");
    assert_eq!(three_of_five_function.asm[3], OP_CHECKSIGADD);
    assert_eq!(three_of_five_function.asm[4], "<signer2>");
    assert_eq!(three_of_five_function.asm[5], OP_CHECKSIGADD);
    assert_eq!(three_of_five_function.asm[6], "<signer3>");
    assert_eq!(three_of_five_function.asm[7], OP_CHECKSIGADD);
    assert_eq!(three_of_five_function.asm[8], "<signer4>");
    assert_eq!(three_of_five_function.asm[9], OP_CHECKSIGADD);
    assert_eq!(three_of_five_function.asm[10], OP_3);
    assert_eq!(three_of_five_function.asm[11], OP_NUMEQUAL);
    assert_eq!(three_of_five_function.asm[12], "144");
    assert_eq!(three_of_five_function.asm[13], OP_CHECKSEQUENCEVERIFY);
    assert_eq!(three_of_five_function.asm[14], OP_DROP);
}

#[test]
fn test_threshold_multisig_should_fail_on_m_greater_than_n() {
    // Threshold multisig example source code
    let threshold_multisig_code = r#"// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;

  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract ThresholdMultisig(
  pubkey signer,
  pubkey signer1,
  pubkey signer2,
  pubkey server
) {
  // m-of-n using literal threshold greater than number of pubkeys
  // Should fail to compile
  function fourOfThree(signature signerSig, signature signer1Sig, signature signer2Sig) {
    require(checkMultisig([signer, signer1, signer2], 4));
  }
}"#;

    let result = compile(threshold_multisig_code);
    assert!(
        result.is_err(),
        "Expected compilation to fail for m > n threshold multisig"
    );
}

#[test]
fn test_threshold_multisig_should_fail_on_m_equal_to_zero() {
    // Threshold multisig example source code
    let threshold_multisig_code = r#"// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;

  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract ThresholdMultisig(
  pubkey signer,
  pubkey signer1,
  pubkey signer2,
  pubkey server
) {
  // m-of-n using literal threshold greater equal to zero
  // Should fail to compile
  function zeroOfThree(signature signerSig, signature signer1Sig, signature signer2Sig) {
    require(checkMultisig([signer, signer1, signer2], 0));
  }
}"#;

    let result = compile(threshold_multisig_code);
    assert!(
        result.is_err(),
        "Expected compilation to fail for m = 0 threshold multisig"
    );
}

#[test]
fn test_threshold_multisig_should_fail_on_n_greater_than_max() {
    // Threshold multisig example source code
    let threshold_multisig_code = r#"// Contract configuration options
options {
  // Server key parameter from contract parameters
  server = server;

  // Exit timelock: 24 hours (144 blocks)
  exit = 144;
}

contract ThresholdMultisig(
  pubkey signer,
  pubkey signer1,
  pubkey signer2,
  pubkey server
) {
  // m-of-n using literal threshold greater than the maximum threshold allowed (999)
  // Should fail to compile
  function thousandFiveOfThousandFive(signature signerSig, signature signer1Sig, signature signer2Sig) {
    require(checkMultisig([
    signer, signer1, signer2, signer3, signer4, signer5, signer6, signer7, signer8, signer9,
    signer10, signer11, signer12, signer13, signer14, signer15, signer16, signer17, signer18, signer19,
    signer20, signer21, signer22, signer23, signer24, signer25, signer26, signer27, signer28, signer29,
    signer30, signer31, signer32, signer33, signer34, signer35, signer36, signer37, signer38, signer39,
    signer40, signer41, signer42, signer43, signer44, signer45, signer46, signer47, signer48, signer49,
    signer50, signer51, signer52, signer53, signer54, signer55, signer56, signer57, signer58, signer59,
    signer60, signer61, signer62, signer63, signer64, signer65, signer66, signer67, signer68, signer69,
    signer70, signer71, signer72, signer73, signer74, signer75, signer76, signer77, signer78, signer79,
    signer80, signer81, signer82, signer83, signer84, signer85, signer86, signer87, signer88, signer89,
    signer90, signer91, signer92, signer93, signer94, signer95, signer96, signer97, signer98, signer99,
    signer100, signer101, signer102, signer103, signer104, signer105, signer106, signer107, signer108, signer109,
    signer110, signer111, signer112, signer113, signer114, signer115, signer116, signer117, signer118, signer119,
    signer120, signer121, signer122, signer123, signer124, signer125, signer126, signer127, signer128, signer129,
    signer130, signer131, signer132, signer133, signer134, signer135, signer136, signer137, signer138, signer139,
    signer140, signer141, signer142, signer143, signer144, signer145, signer146, signer147, signer148, signer149,
    signer150, signer151, signer152, signer153, signer154, signer155, signer156, signer157, signer158, signer159,
    signer160, signer161, signer162, signer163, signer164, signer165, signer166, signer167, signer168, signer169,
    signer170, signer171, signer172, signer173, signer174, signer175, signer176, signer177, signer178, signer179,
    signer180, signer181, signer182, signer183, signer184, signer185, signer186, signer187, signer188, signer189,
    signer190, signer191, signer192, signer193, signer194, signer195, signer196, signer197, signer198, signer199,
    signer200, signer201, signer202, signer203, signer204, signer205, signer206, signer207, signer208, signer209,
    signer210, signer211, signer212, signer213, signer214, signer215, signer216, signer217, signer218, signer219,
    signer220, signer221, signer222, signer223, signer224, signer225, signer226, signer227, signer228, signer229,
    signer230, signer231, signer232, signer233, signer234, signer235, signer236, signer237, signer238, signer239,
    signer240, signer241, signer242, signer243, signer244, signer245, signer246, signer247, signer248, signer249,
    signer250, signer251, signer252, signer253, signer254, signer255, signer256, signer257, signer258, signer259,
    signer260, signer261, signer262, signer263, signer264, signer265, signer266, signer267, signer268, signer269,
    signer270, signer271, signer272, signer273, signer274, signer275, signer276, signer277, signer278, signer279,
    signer280, signer281, signer282, signer283, signer284, signer285, signer286, signer287, signer288, signer289,
    signer290, signer291, signer292, signer293, signer294, signer295, signer296, signer297, signer298, signer299,
    signer300, signer301, signer302, signer303, signer304, signer305, signer306, signer307, signer308, signer309,
    signer310, signer311, signer312, signer313, signer314, signer315, signer316, signer317, signer318, signer319,
    signer320, signer321, signer322, signer323, signer324, signer325, signer326, signer327, signer328, signer329,
    signer330, signer331, signer332, signer333, signer334, signer335, signer336, signer337, signer338, signer339,
    signer340, signer341, signer342, signer343, signer344, signer345, signer346, signer347, signer348, signer349,
    signer350, signer351, signer352, signer353, signer354, signer355, signer356, signer357, signer358, signer359,
    signer360, signer361, signer362, signer363, signer364, signer365, signer366, signer367, signer368, signer369,
    signer370, signer371, signer372, signer373, signer374, signer375, signer376, signer377, signer378, signer379,
    signer380, signer381, signer382, signer383, signer384, signer385, signer386, signer387, signer388, signer389,
    signer390, signer391, signer392, signer393, signer394, signer395, signer396, signer397, signer398, signer399,
    signer400, signer401, signer402, signer403, signer404, signer405, signer406, signer407, signer408, signer409,
    signer410, signer411, signer412, signer413, signer414, signer415, signer416, signer417, signer418, signer419,
    signer420, signer421, signer422, signer423, signer424, signer425, signer426, signer427, signer428, signer429,
    signer430, signer431, signer432, signer433, signer434, signer435, signer436, signer437, signer438, signer439,
    signer440, signer441, signer442, signer443, signer444, signer445, signer446, signer447, signer448, signer449,
    signer450, signer451, signer452, signer453, signer454, signer455, signer456, signer457, signer458, signer459,
    signer460, signer461, signer462, signer463, signer464, signer465, signer466, signer467, signer468, signer469,
    signer470, signer471, signer472, signer473, signer474, signer475, signer476, signer477, signer478, signer479,
    signer480, signer481, signer482, signer483, signer484, signer485, signer486, signer487, signer488, signer489,
    signer490, signer491, signer492, signer493, signer494, signer495, signer496, signer497, signer498, signer499,
    signer500, signer501, signer502, signer503, signer504, signer505, signer506, signer507, signer508, signer509,
    signer510, signer511, signer512, signer513, signer514, signer515, signer516, signer517, signer518, signer519,
    signer520, signer521, signer522, signer523, signer524, signer525, signer526, signer527, signer528, signer529,
    signer530, signer531, signer532, signer533, signer534, signer535, signer536, signer537, signer538, signer539,
    signer540, signer541, signer542, signer543, signer544, signer545, signer546, signer547, signer548, signer549,
    signer550, signer551, signer552, signer553, signer554, signer555, signer556, signer557, signer558, signer559,
    signer560, signer561, signer562, signer563, signer564, signer565, signer566, signer567, signer568, signer569,
    signer570, signer571, signer572, signer573, signer574, signer575, signer576, signer577, signer578, signer579,
    signer580, signer581, signer582, signer583, signer584, signer585, signer586, signer587, signer588, signer589,
    signer590, signer591, signer592, signer593, signer594, signer595, signer596, signer597, signer598, signer599,
    signer600, signer601, signer602, signer603, signer604, signer605, signer606, signer607, signer608, signer609,
    signer610, signer611, signer612, signer613, signer614, signer615, signer616, signer617, signer618, signer619,
    signer620, signer621, signer622, signer623, signer624, signer625, signer626, signer627, signer628, signer629,
    signer630, signer631, signer632, signer633, signer634, signer635, signer636, signer637, signer638, signer639,
    signer640, signer641, signer642, signer643, signer644, signer645, signer646, signer647, signer648, signer649,
    signer650, signer651, signer652, signer653, signer654, signer655, signer656, signer657, signer658, signer659,
    signer660, signer661, signer662, signer663, signer664, signer665, signer666, signer667, signer668, signer669,
    signer670, signer671, signer672, signer673, signer674, signer675, signer676, signer677, signer678, signer679,
    signer680, signer681, signer682, signer683, signer684, signer685, signer686, signer687, signer688, signer689,
    signer690, signer691, signer692, signer693, signer694, signer695, signer696, signer697, signer698, signer699,
    signer700, signer701, signer702, signer703, signer704, signer705, signer706, signer707, signer708, signer709,
    signer710, signer711, signer712, signer713, signer714, signer715, signer716, signer717, signer718, signer719,
    signer720, signer721, signer722, signer723, signer724, signer725, signer726, signer727, signer728, signer729,
    signer730, signer731, signer732, signer733, signer734, signer735, signer736, signer737, signer738, signer739,
    signer740, signer741, signer742, signer743, signer744, signer745, signer746, signer747, signer748, signer749,
    signer750, signer751, signer752, signer753, signer754, signer755, signer756, signer757, signer758, signer759,
    signer760, signer761, signer762, signer763, signer764, signer765, signer766, signer767, signer768, signer769,
    signer770, signer771, signer772, signer773, signer774, signer775, signer776, signer777, signer778, signer779,
    signer780, signer781, signer782, signer783, signer784, signer785, signer786, signer787, signer788, signer789,
    signer790, signer791, signer792, signer793, signer794, signer795, signer796, signer797, signer798, signer799,
    signer800, signer801, signer802, signer803, signer804, signer805, signer806, signer807, signer808, signer809,
    signer810, signer811, signer812, signer813, signer814, signer815, signer816, signer817, signer818, signer819,
    signer820, signer821, signer822, signer823, signer824, signer825, signer826, signer827, signer828, signer829,
    signer830, signer831, signer832, signer833, signer834, signer835, signer836, signer837, signer838, signer839,
    signer840, signer841, signer842, signer843, signer844, signer845, signer846, signer847, signer848, signer849,
    signer850, signer851, signer852, signer853, signer854, signer855, signer856, signer857, signer858, signer859,
    signer860, signer861, signer862, signer863, signer864, signer865, signer866, signer867, signer868, signer869,
    signer870, signer871, signer872, signer873, signer874, signer875, signer876, signer877, signer878, signer879,
    signer880, signer881, signer882, signer883, signer884, signer885, signer886, signer887, signer888, signer889,
    signer890, signer891, signer892, signer893, signer894, signer895, signer896, signer897, signer898, signer899,
    signer900, signer901, signer902, signer903, signer904, signer905, signer906, signer907, signer908, signer909,
    signer910, signer911, signer912, signer913, signer914, signer915, signer916, signer917, signer918, signer919,
    signer920, signer921, signer922, signer923, signer924, signer925, signer926, signer927, signer928, signer929,
    signer930, signer931, signer932, signer933, signer934, signer935, signer936, signer937, signer938, signer939,
    signer940, signer941, signer942, signer943, signer944, signer945, signer946, signer947, signer948, signer949,
    signer950, signer951, signer952, signer953, signer954, signer955, signer956, signer957, signer958, signer959,
    signer960, signer961, signer962, signer963, signer964, signer965, signer966, signer967, signer968, signer969,
    signer970, signer971, signer972, signer973, signer974, signer975, signer976, signer977, signer978, signer979,
    signer980, signer981, signer982, signer983, signer984, signer985, signer986, signer987, signer988, signer989,
    signer990, signer991, signer992, signer993, signer994, signer995, signer996, signer997, signer998, signer999,
    signer1000, signer1001, signer1002, signer1003, signer1004]));
  }
}"#;

    let result = compile(threshold_multisig_code);
    assert!(
        result.is_err(),
        "Expected compilation to fail for m > 999 threshold multisig"
    );
}

#[test]
fn test_threshold_multisig_cli() {
    // Create a temporary directory for our test files
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("threshold_multisig.ark");
    let output_path = temp_dir.path().join("threshold_multisig.json");

    // Write the contract to a file
    fs::write(&input_path, THRESHOLD_MULTISIG_CODE).unwrap();

    // Compile the contract using the library
    let result = compile(THRESHOLD_MULTISIG_CODE);
    assert!(result.is_ok());

    // Run the CLI command
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_arkadec"))
        .arg(input_path.to_str().unwrap())
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .status()
        .expect("Failed to execute command");

    assert!(status.success());

    // Read the output file
    let actual_json_str = fs::read_to_string(&output_path).unwrap();

    // Parse both JSONs to compare them ignoring the updatedAt field
    let mut expected_output = result.unwrap();
    expected_output.updated_at = None; // Remove the timestamp for comparison
    let expected_json_str = serde_json::to_string_pretty(&expected_output).unwrap();

    let mut actual_json: Value = serde_json::from_str(&actual_json_str).unwrap();
    if let Some(obj) = actual_json.as_object_mut() {
        obj.remove("updatedAt"); // Remove the timestamp for comparison
    }
    let actual_json_str = serde_json::to_string_pretty(&actual_json).unwrap();

    let mut expected_json: Value = serde_json::from_str(&expected_json_str).unwrap();
    if let Some(obj) = expected_json.as_object_mut() {
        obj.remove("updatedAt"); // Remove the timestamp for comparison
    }
    let expected_json_str = serde_json::to_string_pretty(&expected_json).unwrap();

    // Compare the outputs
    assert_eq!(actual_json_str, expected_json_str);
}
