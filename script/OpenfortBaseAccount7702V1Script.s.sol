// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {OpenfortBaseAccount7702V1} from "contracts/core/OpenfortBaseAccount7702V1.sol";

contract OpenfortBaseAccount7702V1Deployer is Script {
    address public ENTRY_POINT;
    address public WEBAUTHN_VERIFIER;

    function run() external returns (OpenfortBaseAccount7702V1) {
        ENTRY_POINT = 0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B;
        WEBAUTHN_VERIFIER = 0xc3F5De14f8925cAB747a531B53FE2094C2C5f597;
        vm.startBroadcast();
        OpenfortBaseAccount7702V1 openfortBaseAccount = new OpenfortBaseAccount7702V1(ENTRY_POINT, WEBAUTHN_VERIFIER);
        vm.stopBroadcast();
        return openfortBaseAccount;
    }
}
