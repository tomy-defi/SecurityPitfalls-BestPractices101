# [SecurityPitfalls-BestPractices101](https://secureum.substack.com/p/security-pitfalls-and-best-practices-101)

Now: 7/101

## 1. **Solidity versions**

Using very old versions of Solidity prevents the benefits of bug fixes and newer security checks. Using the latest versions might make contracts susceptible to undiscovered compiler bugs. Consider using one of these versions: *0.7.5, 0.7.6 or 0.8.4*

```solidity
/* 🙅‍♂️ */
pragma solidity ^0.4.25;

/* 🙆‍♂️ */
pragma solidity ^0.8.4;
```

[https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity)

## 2. **Unlocked pragma**

Locking the pragma helps to ensure that contracts do not accidentally get deployed using, for example, an outdated compiler version that might introduce bugs that affect the contract system negatively.

```solidity
/* 🙅‍♂️ */
pragma solidity ^0.8.4;

/* 🙆‍♂️ */
pragma solidity =0.8.4;
```

[https://swcregistry.io/docs/SWC-103](https://swcregistry.io/docs/SWC-103)
[https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Pool.sol#L2](https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Pool.sol#L2)

## 3. **Multiple Solidity pragma**

It is better to use one Solidity compiler version across all contracts instead of different versions with different bugs and security checks.

```solidity
/* 🙅‍♂️ */
// Sample1.sol
pragma solidity =0.8.4;
// Sample2.sol
pragma solidity =0.8.0;

/* 🙆‍♂️ */
// Sample1.sol
pragma solidity =0.8.4;
// Sample2.sol
pragma solidity =0.8.4;
```

[https://github.com/crytic/slither/wiki/Detector-Documentation#different-pragma-directives-are-used](https://github.com/crytic/slither/wiki/Detector-Documentation#different-pragma-directives-are-used)

## 4. **Incorrect access control**

Contract functions executing critical logic should have appropriate access control enforced via address checks (e.g. owner, controller etc.) typically in modifiers. Missing checks allow attackers to control critical logic.

```solidity
/* 🙅‍♂️ */
address owner;
function setOwner() public {
	owner = msg.sender;
}

/* 🙆‍♂️ */
address owner;
error OnlyOwner(address caller);
function setOwner() public {
	// custom error is cheaper than require
	if(msg.sender != owner) revert OnlyOwner(msg.sender);
	owner = msg.sender;
}
```

[https://docs.openzeppelin.com/contracts/3.x/api/access](https://docs.openzeppelin.com/contracts/3.x/api/access)
[https://dasp.co/#item-2](https://dasp.co/#item-2)
[https://solidity-by-example.org/error/](https://solidity-by-example.org/error/)

## 5. **Unprotected withdraw function**

Unprotected (*external*/*public*) function calls sending Ether/tokens to user-controlled addresses may allow users to withdraw unauthorized funds.

```solidity
/* 🙅‍♂️ */
mapping(address => uint256) public balanceOf;

function withdraw(address user, uint256 numTokens) public {
    require(balanceOf[user] >= numTokens);
    balanceOf[user] -= numTokens;
    user.transfer(numTokens * 1 ether);
}

/* 🙆‍♂️ */
mapping(address => uint256) public balanceOf;

function withdraw(address user, uint256 numTokens) public {
		require(user == msg.sender); **// add**
    require(balanceOf[user] >= numTokens);
    balanceOf[user] -= numTokens;
    user.transfer(numTokens * 1 ether);
}
```

[https://swcregistry.io/docs/SWC-105](https://swcregistry.io/docs/SWC-105)
[https://solidity-by-example.org/defi/vault/](https://solidity-by-example.org/defi/vault/)

## 6. **Unprotected call to *selfdestruct***

A user/attacker can mistakenly/intentionally kill the contract. 
Protect access to such functions.

```solidity
/* 🙅‍♂️ */
contract Bad {
	function badDelegate(address _yourContract, bytes calldata _data) 
		payable 
		public 
		returns (bytes memory) {
	    (bool success, bytes memory data) =  _yourContract.delegatecall(_data);
	    require(success);
	    return data;
	}
}
/* Vulnerability
Anyone can destroy the Bad contract using by “selfdestruct” 
because in the context of delegatecall, 
msg.sender will be BadContract even the caller is anyone.
*/

/* 🙆‍♂️ */
contract Good {
	mapping(address => bool) whitelist; //add
	function goodDelegate(address _yourContract, bytes calldata _data) 
		payable 
		public 
		returns (bytes memory) {
			require(whitelist[msg.sender]); //add
	    (bool success, bytes memory data) =  _yourContract.delegatecall(_data);
	    require(success);
	    return data;
	}
}
```

[https://swcregistry.io/docs/SWC-106](https://swcregistry.io/docs/SWC-106)
[https://solidity-by-example.org/delegatecall/](https://solidity-by-example.org/delegatecall/)
[https://solidity-by-example.org/hacks/self-destruct/](https://solidity-by-example.org/hacks/self-destruct/)
[https://medium.com/coinmonks/delegatecall-calling-another-contract-function-in-solidity-b579f804178c](https://medium.com/coinmonks/delegatecall-calling-another-contract-function-in-solidity-b579f804178c)

## 7. **Modifier side-effects**

The modifier should be simple and shouldn’t call external contracts to be easy to read for dev.

```solidity
/* 🙅‍♂️ */
contract BadGuy {
    function isLove(address _addr) external returns(bool) {}
}

contract BadGirl {
    BadGuy badguy;
    modifier isCheck(address _addr) {
        require(badguy.isLove(_addr));
        _;
    }
    function check() isCheck(msg.sender) public {}
}

/* 🙆‍♂️ */
contract GoodGirl {
		mapping(address => bool) love;
    modifier isCheck(address _addr) {
        require(love[msg.sender],"Insufficient Love, try again");
        _;
    }
    function check() isCheck(msg.sender) private {}
}
```

[https://consensys.net/blog/developers/solidity-best-practices-for-smart-contract-security/](https://consensys.net/blog/developers/solidity-best-practices-for-smart-contract-security/)
[https://docs.soliditylang.org/en/develop/security-considerations.html#use-the-checks-effects-interactions-pattern](https://docs.soliditylang.org/en/develop/security-considerations.html#use-the-checks-effects-interactions-pattern)
