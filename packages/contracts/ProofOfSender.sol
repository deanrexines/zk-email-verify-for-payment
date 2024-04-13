// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import "@zk-email/contracts/utils/StringUtils.sol";
import { Verifier } from "./Verifier.sol";


contract ProofOfSender {
    using StringUtils for *;
    
    uint VERIFICATION_REWARD = 1 ether; 

    uint16 public constant bytesInPackedBytes = 31;
    string constant domain = "gmail.com";
    
    uint32 public constant pubKeyHashIndexInSignals = 0; // index of DKIM public key hash in signals array
    uint32 public constant usernameIndexInSignals = 1; // index of first packed Gmail username in signals array
    uint32 public constant usernameLengthInSignals = 1; // length of packed Gmail username in signals array
    uint32 public constant addressIndexInSignals = 2; // index of ethereum address in signals array

    DKIMRegistry dkimRegistry;
    Verifier public immutable verifier;

    mapping(uint256 => string) public tokenIDToName;

    constructor(Verifier v, DKIMRegistry d) ERC721("VerifiedEmail", "VerifiedEmail") payable {
        verifier = v;
        dkimRegistry = d;
    }

    function _domainCheck(uint256[] memory headerSignals) public pure returns (bool) {
        string memory senderBytes = StringUtils.convertPackedBytesToString(headerSignals, 18, bytesInPackedBytes);
        string[2] memory domainStrings = ["verify@x.com", "info@x.com"];
        return
            StringUtils.stringEq(senderBytes, domainStrings[0]) || StringUtils.stringEq(senderBytes, domainStrings[1]);
    }

    /// Send ETH to user wallet if they're able to prove Gmail account ownership by verifying proof of email
    /// @param proof ZK proof of the circuit - a[2], b[4] and c[2] encoded in series
    /// @param signals Public signals of the circuit. First item is pubkey_hash, next 3 are Gmail username, the last one is etherum address
    function mint(uint256[8] memory proof, uint256[3] memory signals) public {
        // Verify the DKIM public key hash stored on-chain matches the one used in circuit
        bytes32 dkimPublicKeyHashInCircuit = bytes32(signals[pubKeyHashIndexInSignals]);
        require(dkimRegistry.isDKIMPublicKeyHashValid(domain, dkimPublicKeyHashInCircuit), "invalid dkim signature"); 

        // Veiry RSA and proof
        require(
            verifier.verifyProof(
                [proof[0], proof[1]],
                [[proof[2], proof[3]], [proof[4], proof[5]]],
                [proof[6], proof[7]],
                signals
            ),
            "Invalid Proof"
        );

        // Extract the username chunks from the signals. 
        // Note that this is not relevant now as username can fit in one signal
        // TODO: Simplify signal uint to string conversion
        uint256[] memory usernamePack = new uint256[](usernameLengthInSignals);
        for (uint256 i = usernameIndexInSignals; i < (usernameIndexInSignals + usernameLengthInSignals); i++) {
            usernamePack[i - usernameIndexInSignals] = signals[i];
        }

        // Send 1 eth to verifier if proof is valid
        uint256 tokenId = tokenCounter.current() + 1;
        address(signals[addressIndexInSignals]).call{value: VERIFICATION_REWARD}("");
        require(sent, "Failed to send Ether to verifier");
    }
}