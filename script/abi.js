export const abi = [
    {
       "type":"constructor",
       "inputs":[
          {
             "name":"_entryPoint",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"_webAuthnVerifier",
             "type":"address",
             "internalType":"address"
          }
       ],
       "stateMutability":"nonpayable"
    },
    {
       "type":"receive",
       "stateMutability":"payable"
    },
    {
       "type":"function",
       "name":"MAX_SELECTORS",
       "inputs":[
          
       ],
       "outputs":[
          {
             "name":"",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"USEROP_TYPEHASH",
       "inputs":[
          
       ],
       "outputs":[
          {
             "name":"",
             "type":"bytes32",
             "internalType":"bytes32"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"_OPENFORT_CONTRACT_ADDRESS",
       "inputs":[
          
       ],
       "outputs":[
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"eip712Domain",
       "inputs":[
          
       ],
       "outputs":[
          {
             "name":"fields",
             "type":"bytes1",
             "internalType":"bytes1"
          },
          {
             "name":"name",
             "type":"string",
             "internalType":"string"
          },
          {
             "name":"version",
             "type":"string",
             "internalType":"string"
          },
          {
             "name":"chainId",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"verifyingContract",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"salt",
             "type":"bytes32",
             "internalType":"bytes32"
          },
          {
             "name":"extensions",
             "type":"uint256[]",
             "internalType":"uint256[]"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"encodeEOASignature",
       "inputs":[
          {
             "name":"_signature",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "stateMutability":"pure"
    },
    {
       "type":"function",
       "name":"encodeWebAuthnSignature",
       "inputs":[
          {
             "name":"challenge",
             "type":"bytes",
             "internalType":"bytes"
          },
          {
             "name":"requireUserVerification",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"authenticatorData",
             "type":"bytes",
             "internalType":"bytes"
          },
          {
             "name":"clientDataJSON",
             "type":"string",
             "internalType":"string"
          },
          {
             "name":"challengeIndex",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"typeIndex",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"r",
             "type":"bytes32",
             "internalType":"bytes32"
          },
          {
             "name":"s",
             "type":"bytes32",
             "internalType":"bytes32"
          },
          {
             "name":"pubKey",
             "type":"tuple",
             "internalType":"struct ISessionKey.PubKey",
             "components":[
                {
                   "name":"x",
                   "type":"bytes32",
                   "internalType":"bytes32"
                },
                {
                   "name":"y",
                   "type":"bytes32",
                   "internalType":"bytes32"
                }
             ]
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "stateMutability":"pure"
    },
    {
       "type":"function",
       "name":"entryPoint",
       "inputs":[
          
       ],
       "outputs":[
          {
             "name":"",
             "type":"address",
             "internalType":"contract IEntryPoint"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"execute",
       "inputs":[
          {
             "name":"_transactions",
             "type":"tuple[]",
             "internalType":"struct OpenfortBaseAccount7702V1SessionKey.Transaction[]",
             "components":[
                {
                   "name":"to",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"value",
                   "type":"uint256",
                   "internalType":"uint256"
                },
                {
                   "name":"data",
                   "type":"bytes",
                   "internalType":"bytes"
                }
             ]
          }
       ],
       "outputs":[
          
       ],
       "stateMutability":"payable"
    },
    {
       "type":"function",
       "name":"execute",
       "inputs":[
          {
             "name":"target",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"value",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"data",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "outputs":[
          
       ],
       "stateMutability":"nonpayable"
    },
    {
       "type":"function",
       "name":"executeBatch",
       "inputs":[
          {
             "name":"calls",
             "type":"tuple[]",
             "internalType":"struct BaseAccount.Call[]",
             "components":[
                {
                   "name":"target",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"value",
                   "type":"uint256",
                   "internalType":"uint256"
                },
                {
                   "name":"data",
                   "type":"bytes",
                   "internalType":"bytes"
                }
             ]
          }
       ],
       "outputs":[
          
       ],
       "stateMutability":"nonpayable"
    },
    {
       "type":"function",
       "name":"getDigestToSign",
       "inputs":[
          {
             "name":"hash",
             "type":"bytes32",
             "internalType":"bytes32"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bytes32",
             "internalType":"bytes32"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"getKeyById",
       "inputs":[
          {
             "name":"_id",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"tuple",
             "internalType":"struct ISessionKey.Key",
             "components":[
                {
                   "name":"pubKey",
                   "type":"tuple",
                   "internalType":"struct ISessionKey.PubKey",
                   "components":[
                      {
                         "name":"x",
                         "type":"bytes32",
                         "internalType":"bytes32"
                      },
                      {
                         "name":"y",
                         "type":"bytes32",
                         "internalType":"bytes32"
                      }
                   ]
                },
                {
                   "name":"eoaAddress",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"keyType",
                   "type":"uint8",
                   "internalType":"enum ISessionKey.KeyType"
                }
             ]
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"getKeyRegistrationInfo",
       "inputs":[
          {
             "name":"_id",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "outputs":[
          {
             "name":"keyType",
             "type":"uint8",
             "internalType":"enum ISessionKey.KeyType"
          },
          {
             "name":"registeredBy",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"isActive",
             "type":"bool",
             "internalType":"bool"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"getNonce",
       "inputs":[
          
       ],
       "outputs":[
          {
             "name":"",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"getSessionKeyData",
       "inputs":[
          {
             "name":"_key",
             "type":"address",
             "internalType":"address"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"",
             "type":"uint48",
             "internalType":"uint48"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"getSessionKeyData",
       "inputs":[
          {
             "name":"_keyHash",
             "type":"bytes32",
             "internalType":"bytes32"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"",
             "type":"uint48",
             "internalType":"uint48"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"getUserOpHash",
       "inputs":[
          {
             "name":"userOp",
             "type":"tuple",
             "internalType":"struct PackedUserOperation",
             "components":[
                {
                   "name":"sender",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"nonce",
                   "type":"uint256",
                   "internalType":"uint256"
                },
                {
                   "name":"initCode",
                   "type":"bytes",
                   "internalType":"bytes"
                },
                {
                   "name":"callData",
                   "type":"bytes",
                   "internalType":"bytes"
                },
                {
                   "name":"accountGasLimits",
                   "type":"bytes32",
                   "internalType":"bytes32"
                },
                {
                   "name":"preVerificationGas",
                   "type":"uint256",
                   "internalType":"uint256"
                },
                {
                   "name":"gasFees",
                   "type":"bytes32",
                   "internalType":"bytes32"
                },
                {
                   "name":"paymasterAndData",
                   "type":"bytes",
                   "internalType":"bytes"
                },
                {
                   "name":"signature",
                   "type":"bytes",
                   "internalType":"bytes"
                }
             ]
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bytes32",
             "internalType":"bytes32"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"idSessionKeys",
       "inputs":[
          {
             "name":"id",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "outputs":[
          {
             "name":"pubKey",
             "type":"tuple",
             "internalType":"struct ISessionKey.PubKey",
             "components":[
                {
                   "name":"x",
                   "type":"bytes32",
                   "internalType":"bytes32"
                },
                {
                   "name":"y",
                   "type":"bytes32",
                   "internalType":"bytes32"
                }
             ]
          },
          {
             "name":"eoaAddress",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"keyType",
             "type":"uint8",
             "internalType":"enum ISessionKey.KeyType"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"initialize",
       "inputs":[
          {
             "name":"_owner",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"_validUntil",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"userOpHash",
             "type":"bytes32",
             "internalType":"bytes32"
          },
          {
             "name":"_signature",
             "type":"bytes",
             "internalType":"bytes"
          },
          {
             "name":"_nonce",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "outputs":[
          
       ],
       "stateMutability":"nonpayable"
    },
    {
       "type":"function",
       "name":"isSessionKeyActive",
       "inputs":[
          {
             "name":"keyHash",
             "type":"bytes32",
             "internalType":"bytes32"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bool",
             "internalType":"bool"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"isSessionKeyActive",
       "inputs":[
          {
             "name":"eoaKey",
             "type":"address",
             "internalType":"address"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bool",
             "internalType":"bool"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"isValidSignature",
       "inputs":[
          {
             "name":"_hash",
             "type":"bytes32",
             "internalType":"bytes32"
          },
          {
             "name":"_signature",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "outputs":[
          {
             "name":"magicValue",
             "type":"bytes4",
             "internalType":"bytes4"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"nonce",
       "inputs":[
          
       ],
       "outputs":[
          {
             "name":"",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"onERC1155BatchReceived",
       "inputs":[
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"",
             "type":"uint256[]",
             "internalType":"uint256[]"
          },
          {
             "name":"",
             "type":"uint256[]",
             "internalType":"uint256[]"
          },
          {
             "name":"",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bytes4",
             "internalType":"bytes4"
          }
       ],
       "stateMutability":"pure"
    },
    {
       "type":"function",
       "name":"onERC1155Received",
       "inputs":[
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bytes4",
             "internalType":"bytes4"
          }
       ],
       "stateMutability":"pure"
    },
    {
       "type":"function",
       "name":"onERC721Received",
       "inputs":[
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bytes4",
             "internalType":"bytes4"
          }
       ],
       "stateMutability":"pure"
    },
    {
       "type":"function",
       "name":"owner",
       "inputs":[
          
       ],
       "outputs":[
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"registerSessionKey",
       "inputs":[
          {
             "name":"_key",
             "type":"tuple",
             "internalType":"struct ISessionKey.Key",
             "components":[
                {
                   "name":"pubKey",
                   "type":"tuple",
                   "internalType":"struct ISessionKey.PubKey",
                   "components":[
                      {
                         "name":"x",
                         "type":"bytes32",
                         "internalType":"bytes32"
                      },
                      {
                         "name":"y",
                         "type":"bytes32",
                         "internalType":"bytes32"
                      }
                   ]
                },
                {
                   "name":"eoaAddress",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"keyType",
                   "type":"uint8",
                   "internalType":"enum ISessionKey.KeyType"
                }
             ]
          },
          {
             "name":"_validUntil",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"_validAfter",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"_limit",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"_whitelisting",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"_contractAddress",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"_spendTokenInfo",
             "type":"tuple",
             "internalType":"struct SpendLimit.SpendTokenInfo",
             "components":[
                {
                   "name":"token",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"limit",
                   "type":"uint256",
                   "internalType":"uint256"
                }
             ]
          },
          {
             "name":"_allowedSelectors",
             "type":"bytes4[]",
             "internalType":"bytes4[]"
          },
          {
             "name":"_ethLimit",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "outputs":[
          
       ],
       "stateMutability":"nonpayable"
    },
    {
       "type":"function",
       "name":"revokeAllSessionKeys",
       "inputs":[
          
       ],
       "outputs":[
          
       ],
       "stateMutability":"nonpayable"
    },
    {
       "type":"function",
       "name":"revokeSessionKey",
       "inputs":[
          {
             "name":"_key",
             "type":"tuple",
             "internalType":"struct ISessionKey.Key",
             "components":[
                {
                   "name":"pubKey",
                   "type":"tuple",
                   "internalType":"struct ISessionKey.PubKey",
                   "components":[
                      {
                         "name":"x",
                         "type":"bytes32",
                         "internalType":"bytes32"
                      },
                      {
                         "name":"y",
                         "type":"bytes32",
                         "internalType":"bytes32"
                      }
                   ]
                },
                {
                   "name":"eoaAddress",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"keyType",
                   "type":"uint8",
                   "internalType":"enum ISessionKey.KeyType"
                }
             ]
          }
       ],
       "outputs":[
          
       ],
       "stateMutability":"nonpayable"
    },
    {
       "type":"function",
       "name":"sessionKeys",
       "inputs":[
          {
             "name":"sessionKey",
             "type":"bytes32",
             "internalType":"bytes32"
          }
       ],
       "outputs":[
          {
             "name":"pubKey",
             "type":"tuple",
             "internalType":"struct ISessionKey.PubKey",
             "components":[
                {
                   "name":"x",
                   "type":"bytes32",
                   "internalType":"bytes32"
                },
                {
                   "name":"y",
                   "type":"bytes32",
                   "internalType":"bytes32"
                }
             ]
          },
          {
             "name":"isActive",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"validUntil",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"validAfter",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"limit",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"masterSessionKey",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"whitelisting",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"spendTokenInfo",
             "type":"tuple",
             "internalType":"struct SpendLimit.SpendTokenInfo",
             "components":[
                {
                   "name":"token",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"limit",
                   "type":"uint256",
                   "internalType":"uint256"
                }
             ]
          },
          {
             "name":"ethLimit",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"whoRegistrated",
             "type":"address",
             "internalType":"address"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"sessionKeysEOA",
       "inputs":[
          {
             "name":"sessionKeyEOA",
             "type":"address",
             "internalType":"address"
          }
       ],
       "outputs":[
          {
             "name":"pubKey",
             "type":"tuple",
             "internalType":"struct ISessionKey.PubKey",
             "components":[
                {
                   "name":"x",
                   "type":"bytes32",
                   "internalType":"bytes32"
                },
                {
                   "name":"y",
                   "type":"bytes32",
                   "internalType":"bytes32"
                }
             ]
          },
          {
             "name":"isActive",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"validUntil",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"validAfter",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"limit",
             "type":"uint48",
             "internalType":"uint48"
          },
          {
             "name":"masterSessionKey",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"whitelisting",
             "type":"bool",
             "internalType":"bool"
          },
          {
             "name":"spendTokenInfo",
             "type":"tuple",
             "internalType":"struct SpendLimit.SpendTokenInfo",
             "components":[
                {
                   "name":"token",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"limit",
                   "type":"uint256",
                   "internalType":"uint256"
                }
             ]
          },
          {
             "name":"ethLimit",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"whoRegistrated",
             "type":"address",
             "internalType":"address"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"supportsInterface",
       "inputs":[
          {
             "name":"interfaceId",
             "type":"bytes4",
             "internalType":"bytes4"
          }
       ],
       "outputs":[
          {
             "name":"",
             "type":"bool",
             "internalType":"bool"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"tokensReceived",
       "inputs":[
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"",
             "type":"address",
             "internalType":"address"
          },
          {
             "name":"",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"",
             "type":"bytes",
             "internalType":"bytes"
          },
          {
             "name":"",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "outputs":[
          
       ],
       "stateMutability":"pure"
    },
    {
       "type":"function",
       "name":"usedChallenges",
       "inputs":[
          {
             "name":"challenge",
             "type":"bytes",
             "internalType":"bytes"
          }
       ],
       "outputs":[
          {
             "name":"isUsed",
             "type":"bool",
             "internalType":"bool"
          }
       ],
       "stateMutability":"view"
    },
    {
       "type":"function",
       "name":"validateUserOp",
       "inputs":[
          {
             "name":"userOp",
             "type":"tuple",
             "internalType":"struct PackedUserOperation",
             "components":[
                {
                   "name":"sender",
                   "type":"address",
                   "internalType":"address"
                },
                {
                   "name":"nonce",
                   "type":"uint256",
                   "internalType":"uint256"
                },
                {
                   "name":"initCode",
                   "type":"bytes",
                   "internalType":"bytes"
                },
                {
                   "name":"callData",
                   "type":"bytes",
                   "internalType":"bytes"
                },
                {
                   "name":"accountGasLimits",
                   "type":"bytes32",
                   "internalType":"bytes32"
                },
                {
                   "name":"preVerificationGas",
                   "type":"uint256",
                   "internalType":"uint256"
                },
                {
                   "name":"gasFees",
                   "type":"bytes32",
                   "internalType":"bytes32"
                },
                {
                   "name":"paymasterAndData",
                   "type":"bytes",
                   "internalType":"bytes"
                },
                {
                   "name":"signature",
                   "type":"bytes",
                   "internalType":"bytes"
                }
             ]
          },
          {
             "name":"userOpHash",
             "type":"bytes32",
             "internalType":"bytes32"
          },
          {
             "name":"missingAccountFunds",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "outputs":[
          {
             "name":"validationData",
             "type":"uint256",
             "internalType":"uint256"
          }
       ],
       "stateMutability":"nonpayable"
    },
    {
       "type":"event",
       "name":"EIP712DomainChanged",
       "inputs":[
          
       ],
       "anonymous":false
    },
    {
       "type":"event",
       "name":"Initialized",
       "inputs":[
          {
             "name":"owner",
             "type":"address",
             "indexed":true,
             "internalType":"address"
          }
       ],
       "anonymous":false
    },
    {
       "type":"event",
       "name":"Initialized",
       "inputs":[
          {
             "name":"version",
             "type":"uint64",
             "indexed":false,
             "internalType":"uint64"
          }
       ],
       "anonymous":false
    },
    {
       "type":"event",
       "name":"SessionKeyRegistrated",
       "inputs":[
          {
             "name":"sessionKey",
             "type":"bytes32",
             "indexed":true,
             "internalType":"bytes32"
          }
       ],
       "anonymous":false
    },
    {
       "type":"event",
       "name":"SessionKeyRevoked",
       "inputs":[
          {
             "name":"sessionKey",
             "type":"bytes32",
             "indexed":true,
             "internalType":"bytes32"
          }
       ],
       "anonymous":false
    },
    {
       "type":"event",
       "name":"TransactionExecuted",
       "inputs":[
          {
             "name":"target",
             "type":"address",
             "indexed":true,
             "internalType":"address"
          },
          {
             "name":"value",
             "type":"uint256",
             "indexed":false,
             "internalType":"uint256"
          },
          {
             "name":"data",
             "type":"bytes",
             "indexed":false,
             "internalType":"bytes"
          }
       ],
       "anonymous":false
    },
    {
       "type":"error",
       "name":"ECDSAInvalidSignature",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"ECDSAInvalidSignatureLength",
       "inputs":[
          {
             "name":"length",
             "type":"uint256",
             "internalType":"uint256"
          }
       ]
    },
    {
       "type":"error",
       "name":"ECDSAInvalidSignatureS",
       "inputs":[
          {
             "name":"s",
             "type":"bytes32",
             "internalType":"bytes32"
          }
       ]
    },
    {
       "type":"error",
       "name":"ExecuteError",
       "inputs":[
          {
             "name":"index",
             "type":"uint256",
             "internalType":"uint256"
          },
          {
             "name":"error",
             "type":"bytes",
             "internalType":"bytes"
          }
       ]
    },
    {
       "type":"error",
       "name":"InvalidInitialization",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"InvalidShortString",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"NotInitializing",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"OpenfortBaseAccount7702V1__InvalidNonce",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"OpenfortBaseAccount7702V1__InvalidSignature",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"OpenfortBaseAccount7702V1__InvalidTransactionLength",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"OpenfortBaseAccount7702V1__InvalidTransactionTarget",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"OpenfortBaseAccount7702V1__OwnableUnauthorizedAccount",
       "inputs":[
          {
             "name":"addr",
             "type":"address",
             "internalType":"address"
          }
       ]
    },
    {
       "type":"error",
       "name":"OpenfortBaseAccount7702V1__TransactionFailed",
       "inputs":[
          {
             "name":"returnData",
             "type":"bytes",
             "internalType":"bytes"
          }
       ]
    },
    {
       "type":"error",
       "name":"OpenfortBaseAccount7702V1__ValidationExpired",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"OpenfortBaseAccount7702V1__WithdrawFailed",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"ReentrancyGuardReentrantCall",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"SafeCastOverflowedUintDowncast",
       "inputs":[
          {
             "name":"bits",
             "type":"uint8",
             "internalType":"uint8"
          },
          {
             "name":"value",
             "type":"uint256",
             "internalType":"uint256"
          }
       ]
    },
    {
       "type":"error",
       "name":"SessionKeyManager__AddressCantBeZero",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"SessionKeyManager__InvalidTimestamp",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"SessionKeyManager__SelectorsListTooBig",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"SessionKeyManager__SessionKeyInactive",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"SessionKeyManager__SessionKeyRegistered",
       "inputs":[
          
       ]
    },
    {
       "type":"error",
       "name":"StringTooLong",
       "inputs":[
          {
             "name":"str",
             "type":"string",
             "internalType":"string"
          }
       ]
    }
 ]