# Openfort EIP-7702 Smart Contract Accounts

<p style="background-color: black; display: inline-block; padding: 5px;">
  <img src="contracts/Logo_black_primary_no_bg.png" alt="Openfort" style="width: 300px;" />
</p>

This documentation covers the implementation of EIP-7702 compatible smart contract accounts by Openfort. These accounts enable account abstraction while leveraging the new capabilities introduced by EIP-7702 (Pectra Upgrade).

## Table of Contents

* [Overview](#overview)
* [Key Features](#key-features)

  * [EIP-7702 Implementation](#eip-7702-implementation)
  * [Session Keys](#session-keys)
  * [WebAuthn Support](#webauthn-support)
  * [Spending Controls](#spending-controls)
  * [Security Features](#security-features)
* [Architecture](#architecture)

  * [Core Components](#core-components)
  * [Storage](#storage)
  * [Key Types](#key-types)
  * [Session Key Structure](#session-key-structure)
  * [EIP-4337 / EIP-7702 Interplay](#eip-4337--eip-7702-interplay)
* [Usage Guide](#usage-guide)

  * [Account Initialization](#account-initialization)
  * [Session Key Management](#session-key-management)
  * [Transaction Execution](#transaction-execution)
* [Security Considerations](#security-considerations)
* [Implementation Details](#implementation-details)

  * [Signature Verification](#signature-verification)
  * [Storage Clearing](#storage-clearing)
* [Examples](#examples)

  * [Registering a WebAuthn Session Key](#registering-a-webauthn-session-key)
  * [Using EOA Session Keys](#using-eoa-session-keys)
* [License](#license)
* [Disclaimer](#disclaimer)
* [Contact](#contact)

## Overview

Openfort's implementation of EIP-7702 (Account Implementation Contract Standard) allows smart contracts to be executed at any address without a deployment transaction. Our primary focus is on:

- **OpenfortBaseAccount7702V1**: A fully-featured ERC-7702 smart account that supports ERC-4337 UserOps and enables temporary "session keys" for gas-sponsored meta-transactions.

## Key Features

### EIP-7702 Implementation

- **No Deployment Transaction**: Create and use accounts without expensive deployment transactions
- **Custom Storage Layout**: Fixed storage layout using a predetermined slot to ensure deterministic access
- **ERC-4337 Compatibility**: Full support for ERC-4337 UserOperations

### Session Keys

Session keys are short-lived externally-owned accounts authorized to execute a restricted subset of calls without holding any ETH. The account owner signs an "authorization payload" specifying:

1. The session key address or public key
2. An optional whitelist of methods and targets
3. An expiry timestamp
4. Optional spending limits for ETH and tokens

### WebAuthn Support

- **Hardware Security Keys**: Full integration with WebAuthn for secure authentication
- **Passkey Authentication**: Use biometric authentication (fingerprint, face recognition) for authorizing transactions

### Spending Controls

- **Token Limits**: Set spending limits for specific ERC-20 tokens
- **ETH Limits**: Restrict how much ETH a session key can use
- **Transaction Counting**: Limit the number of transactions a session key can execute

### Security Features

- **Whitelisting**: Restrict which contracts a session key can interact with
- **Selector Restrictions**: Limit which functions a session key can call
- **Time-Based Expiry**: Automatically invalidate session keys after a specified period
- **Reentrancy Protection**: Built-in guard against reentrancy attacks

## Architecture

### Core Components

#### Storage

The contract uses a fixed storage layout starting at a specific slot:

```solidity
keccak256("openfort.baseAccount.7702.v1") = 0x801ae8efc2175d3d963e799b27e0e948b9a3fa84e2ce105a370245c8c127f368
```

#### Key Types

```solidity
enum KeyType {
    EOA,     // Standard Ethereum account
    WEBAUTHN // WebAuthn/Passkey authentication
}
```

#### Session Key Structure

```solidity
struct SessionKey {
    PubKey pubKey;                   // WebAuthn public key
    bool isActive;                   // Whether key is active
    uint48 validUntil;               // Expiration timestamp
    uint48 validAfter;               // Activation timestamp
    uint48 limit;                    // Max transaction count
    bool masterSessionKey;           // Unrestricted key flag
    bool whitelisting;               // Contract whitelist required
    mapping(address => bool) whitelist; // Approved contracts
    bytes4[] allowedSelectors;       // Approved function signatures
    address whoRegistrated;          // Who registered this key
    uint256 ethLimit;                // Maximum ETH spending
    SpendTokenInfo spendTokenInfo;   // Token spending info
}
```

### EIP-4337 / EIP-7702 Interplay

From the bundler's perspective, the contract behaves like any other account implementing `validateUserOp`. The difference lies in how authorization is handled inside `validateUserOp`, which delegates to either:

- The owner signature, OR
- A valid session key signature if one is supplied

This allows for flexible user experiences while maintaining security.

## Usage Guide

### Account Initialization

Initialize an account with the owner's address:

```solidity
function initialize(address _owner, uint256 _validUntil, bytes32 userOpHash, bytes calldata _signature, uint256 _nonce)
```

### Session Key Management

Register a new session key:

```solidity
function registerSessionKey(
    Key calldata _key,
    uint48 _validUntil,
    uint48 _validAfter,
    uint48 _limit,
    bool _whitelisting,
    address _contractAddress,
    SpendTokenInfo calldata _spendTokenInfo,
    bytes4[] calldata _allowedSelectors,
    uint256 _ethLimit
)
```

Revoke a session key:

```solidity
function revokeSessionKey(Key calldata _key)
```

Revoke all session keys:

```solidity
function revokeAllSessionKeys()
```

### Transaction Execution

Execute a single transaction:

```solidity
function execute(address _target, uint256 _value, bytes calldata _calldata)
```

Execute batch transactions:

```solidity
function execute(Transaction[] calldata _transactions)
```

Execute batch with separate parameters:

```solidity
function executeBatch(address[] calldata _target, uint256[] calldata _value, bytes[] calldata _calldata)
```

## Security Considerations

- **Session Key Limits**: Always set appropriate limits for session keys
- **Whitelisting**: Use contract whitelisting for non-master session keys
- **Expiration Times**: Set reasonable expiration times for session keys
- **WebAuthn Verification**: The contract uses challenge-response to verify WebAuthn signatures
- **EIP-712 Signatures**: The contract uses typed data signing for secure authorization

## Implementation Details

### Signature Verification

The contract supports multiple signature verification methods:

1. **EIP-1271 Verification**: For smart contract signatures
2. **ECDSA Verification**: For standard EOA signatures
3. **WebAuthn Verification**: For hardware security keys and passkeys

### Storage Clearing

The contract provides a `_clearStorage()` function to reset storage slots when reinitializing an account:

```solidity
function _clearStorage() internal {
    bytes32 baseSlot = keccak256("openfort.baseAccount.7702.v1");
    
    for (uint256 i = 2; i < 6; i++) {
        bytes32 slot = bytes32(uint256(baseSlot) + i);
        assembly {
            sstore(slot, 0)
        }
    }
}
```

## Examples

### Registering a WebAuthn Session Key

```solidity
// Create a WebAuthn key structure
PubKey memory pubKey = PubKey({
    x: 0x..., // X coordinate from credential
    y: 0x...  // Y coordinate from credential
});

Key memory key = Key({
    pubKey: pubKey,
    eoaAddress: address(0),
    keyType: KeyType.WEBAUTHN
});

// Create token spending limits
SpendTokenInfo memory tokenInfo = SpendTokenInfo({
    token: address(0x1234...),  // Token contract address
    limit: 100 * 10**18         // 100 tokens
});

// Function selectors to allow
bytes4[] memory selectors = new bytes4[](2);
selectors[0] = bytes4(keccak256("transfer(address,uint256)"));
selectors[1] = bytes4(keccak256("approve(address,uint256)"));

// Register the session key
account.registerSessionKey(
    key,
    uint48(block.timestamp + 1 days),  // Valid until tomorrow
    uint48(block.timestamp),           // Valid from now
    10,                                // Allow 10 transactions
    true,                              // Enable whitelisting
    address(0x5678...),                // Allow this contract
    tokenInfo,                         // Token spending limits
    selectors,                         // Allowed function selectors
    1 ether                            // ETH spending limit
);
```

### Using EOA Session Keys

```solidity
// Create an EOA key structure
Key memory key = Key({
    pubKey: PubKey({x: 0, y: 0}),
    eoaAddress: 0x1234...,
    keyType: KeyType.EOA
});

// Register as a master session key (unlimited permissions)
account.registerSessionKey(
    key,
    uint48(block.timestamp + 7 days),  // Valid for a week
    uint48(block.timestamp),           // Valid from now
    0,                                 // Unlimited transactions (master key)
    false,                             // No whitelisting needed
    address(0),                        // No specific contract
    SpendTokenInfo({token: address(0), limit: 0}), // No token limits
    new bytes4[](0),                   // No selector restrictions
    0                                  // No ETH limit
);
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This contract is a teaching/demo implementation **only**. It is *not* audited for production use.

## Contact

For security inquiries, please contact: security@openfort.xyz