# H-01 Missing Slippage Protection in Perp Depository

## Summary
During the source code review it was possible to identify a vulnerability that would allow an attacker to negatively attack the Perp Clearinghouse interaction of the PerpDepository module by executing a price manipulation and sandwich attack.

A common DeFi protocol vulnerability that arises when a protocol lacks slippage protection is front running. Front running occurs when a malicious actor attempts to take advantage of the speed of their transactions to purchase a certain asset before other buyers can. In a DeFi protocol without slippage protection, a malicious actor can submit a large transaction to purchase a large amount of an asset, causing the asset's price to suddenly spike. This gives the malicious actor an advantage, as they can purchase the asset at a lower price before the price increases due to the sudden demand. This can cause significant losses for other buyers, as they will have to pay a higher price for the asset than the malicious actor.

Sandwich attack is a front-running type of attack and is very common in DeFi, on decentralized exchanges. This kind of attack happens when the attacker is buying and selling on the same block and the victim's transaction falls in the middle, hence the name “sandwich attack”

## Vulnerability Detail
The PerpDepository contract exposes an external _rebalance()_  and _rebalanceLite()_ function that is not protected by any access control. Any user can call and interact with this function.
Furthermore, the function has a input parameter _uint160 sqrtPriceLimitX96_ that is never validated in the contract code.

An attacker can thus call the _rebalance()_ and/or _rebalanceLite()_ function with and set _sqrtPriceLimitX96_ to **0** resulting in PerpDepository.sol opening a position with the Perp clearing house with no slippage protection.


### Call Stack
The data flow in PerpDepository.sol contract for the _rebalance_ function is implement as follows:
<img width="708" alt="callstackPerp" src="https://user-images.githubusercontent.com/102132718/210303230-0c6d4cf7-e462-4082-8bd0-977f013e1bb7.png">


### Reference Perp documentation
https://support.perp.com/hc/en-us/articles/7917807368729-Perp-v2-Integration-Guide-Code-Samples

> sqrtPriceLimitX96: the restriction on the ending price after the swap. **0 for no limit**. This is the same as sqrtPriceLimitX96 in the Uniswap V3 contract.



## Impact
High

## Code Snippet
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L354-L365

### Exploit PoC
Exploit Proof of Concept can be found here:
https://github.com/sherlock-audit/2023-01-uxd/blob/main/script/RebalanceSandwitch.s.sol#L159-L166



## Tool used
Manual Review

## Recommendation
Validate the user supplied input to enforce a minimum slippage. 
Consider implementing Access Control for the rebalance() function


# H-02 uxdController isn't using safeTransfer for ERC20 Transfers

## Summary
When handling ERC20 based user deposits, the UXDController isn't using safeTransfer/safeTransferFrom.

## Vulnerability Detail
UXPController.mint() function solely relies on a revert of the ERC20 contract. Should UXP Protocol in the future use ERC20 contracts that fail silently or return (bool false) when a transaction fails, this could result lost funds to the protocol.


ERC20 https://eips.ethereum.org/EIPS/eip-20
> The transferFrom method is used for a withdraw workflow, allowing contracts to transfer tokens on your behalf. [...] The function **SHOULD** throw unless the _from account has deliberately authorized the sender of the message via some mechanism.

ERC20 standard does not enforce that transferFrom() throws / reverts, if the transfer amount exceeds an account's balance.  For example the LDO or  minime Token implementation does not throw or revert.

## Impact
High.

Loss of funds

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDController.sol#L195-L200


### Exploit Proof of Concept:

https://github.com/sherlock-audit/2023-01-uxd/blob/main/script/ERC20TransferExploit.sol#L118-L149

## Tool used

Manual Review

## Recommendation
Use SafeERC20 Wrappers. 
Wrappers around ERC20 operations that throw on failure (when the token contract returns false). Tokens that return no value (and instead revert or throw on failure) are also supported, non-reverting calls are assumed to be successful. To use this library you can add a using `SafeERC20 for ERC20; `statement to your contract, which allows you to call the safe operations as `token.safeTransfer(…​)`, etc.
