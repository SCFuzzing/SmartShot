pragma solidity ^0.4.18;

 
interface IToken { 

     
    function totalSupply() public view returns (uint);


     
    function balanceOf(address _owner) public view returns (uint);


     
    function transfer(address _to, uint _value) public returns (bool);


     
    function transferFrom(address _from, address _to, uint _value) public returns (bool);


     
    function approve(address _spender, uint _value) public returns (bool);


     
    function allowance(address _owner, address _spender) public view returns (uint);
}


 
interface ICrowdsale {

     
    function isInPresalePhase() public view returns (bool);


     
    function isEnded() public view returns (bool);


     
    function hasBalance(address _beneficiary, uint _releaseDate) public view returns (bool);


     
    function balanceOf(address _owner) public view returns (uint);


     
    function ethBalanceOf(address _owner) public view returns (uint);


     
    function refundableEthBalanceOf(address _owner) public view returns (uint);


     
    function getRate(uint _phase, uint _volume) public view returns (uint);


     
    function toTokens(uint _wei, uint _rate) public view returns (uint);


     
    function () public payable;


     
    function contribute() public payable returns (uint);


     
    function contributeFor(address _beneficiary) public payable returns (uint);


     
    function withdrawTokens() public;


      
    function withdrawTokensTo(address _beneficiary) public;


     
    function withdrawEther() public;


     
    function withdrawEtherTo(address _beneficiary) public;


     
    function refund() public;


     
    function refundTo(address _beneficiary) public;
}


 
contract Dispatchable {


     
    address private target;
}


 
contract SimpleDispatcher {

     
    address private target;


     
    function SimpleDispatcher(address _target) public {
        target = _target;
    }


     
    function () public payable {
        var dest = target;
        assembly {
            calldatacopy(0x0, 0x0, calldatasize)
            switch delegatecall(sub(gas, 10000), dest, 0x0, calldatasize, 0, 0)
            case 0 { revert(0, 0) }  
        }
    }
}


 
contract PersonalCrowdsaleProxyDispatcher is SimpleDispatcher {

     
    address public targetCrowdsale;
    address public targetToken;

     
    address public beneficiary;
    bytes32 private passphraseHash;


     
    function PersonalCrowdsaleProxyDispatcher(address _target, address _targetCrowdsale, address _targetToken, bytes32 _passphraseHash) public 
        SimpleDispatcher(_target) {
        targetCrowdsale = _targetCrowdsale;
        targetToken = _targetToken;
        passphraseHash = _passphraseHash;
    }
}


 
interface ICrowdsaleProxy {

     
    function () public payable;


     
    function contribute() public payable returns (uint);


     
    function contributeFor(address _beneficiary) public payable returns (uint);
}


 
contract CrowdsaleProxy is ICrowdsaleProxy {

    address public owner;
    ICrowdsale public target;
    

     
    function CrowdsaleProxy(address _owner, address _target) public {
        target = ICrowdsale(_target);
        owner = _owner;
    }


     
    function () public payable {
        target.contributeFor.value(msg.value)(msg.sender);
    }


     
    function contribute() public payable returns (uint) {
        target.contributeFor.value(msg.value)(msg.sender);
    }


     
    function contributeFor(address _beneficiary) public payable returns (uint) {
        target.contributeFor.value(msg.value)(_beneficiary);
    }
}


 
interface IPersonalCrowdsaleProxy {


     
    function () public payable;


     
    function invest() public;


     
    function refund() public;


     
    function updateTokenBalance() public;


     
    function withdrawTokens() public;


     
    function updateEtherBalance() public;


     
    function withdrawEther() public;
}


 
contract PersonalCrowdsaleProxy is IPersonalCrowdsaleProxy, Dispatchable {

     
    ICrowdsale public targetCrowdsale;
    IToken public targetToken;

     
    address public beneficiary;
    bytes32 private passphraseHash;


     
    modifier when_beneficiary_is_known() {
        require(beneficiary != address(0));
        _;
    }


     
    modifier when_beneficiary_is_unknown() {
        require(beneficiary == address(0));
        _;
    }


     
    function setBeneficiary(address _beneficiary, bytes32 _passphrase) public when_beneficiary_is_unknown {
        require(keccak256(_passphrase) == passphraseHash);
        beneficiary = _beneficiary;
    }


     
    function () public payable {
         
    }


     
    function invest() public {
        targetCrowdsale.contribute.value(this.balance)();
    }


     
    function refund() public {
        targetCrowdsale.refund();
    }


     
    function updateTokenBalance() public {
        targetCrowdsale.withdrawTokens();
    }


     
    function withdrawTokens() public when_beneficiary_is_known {
        uint balance = targetToken.balanceOf(this);
        targetToken.transfer(beneficiary, balance);
    }


     
    function updateEtherBalance() public {
        targetCrowdsale.withdrawEther();
    }


     
    function withdrawEther() public when_beneficiary_is_known {
        beneficiary.transfer(this.balance);
    }
}


 
contract CrowdsaleProxyFactory {

     
    address public targetCrowdsale;
    address public targetToken;

     
    address private personalCrowdsaleProxyTarget;


     
    event ProxyCreated(address proxy, address beneficiary);


     
    function CrowdsaleProxyFactory(address _targetCrowdsale, address _targetToken) public {
        targetCrowdsale = _targetCrowdsale;
        targetToken = _targetToken;
        personalCrowdsaleProxyTarget = new PersonalCrowdsaleProxy();
    }

    
     
    function createProxyAddress() public returns (address) {
        address proxy = new CrowdsaleProxy(msg.sender, targetCrowdsale);
        ProxyCreated(proxy, msg.sender);
        return proxy;
    }


     
    function createProxyAddressFor(address _beneficiary) public returns (address) {
        address proxy = new CrowdsaleProxy(_beneficiary, targetCrowdsale);
        ProxyCreated(proxy, _beneficiary);
        return proxy;
    }


     
    function createPersonalDepositAddress(bytes32 _passphraseHash) public returns (address) {
        address proxy = new PersonalCrowdsaleProxyDispatcher(
            personalCrowdsaleProxyTarget, targetCrowdsale, targetToken, _passphraseHash);
        ProxyCreated(proxy, msg.sender);
        return proxy;
    }


     
    function createPersonalDepositAddressFor(address _beneficiary) public returns (address) {
        PersonalCrowdsaleProxy proxy = PersonalCrowdsaleProxy(new PersonalCrowdsaleProxyDispatcher(
            personalCrowdsaleProxyTarget, targetCrowdsale, targetToken, keccak256(bytes32(_beneficiary))));
        proxy.setBeneficiary(_beneficiary, bytes32(_beneficiary));
        ProxyCreated(proxy, _beneficiary);
        return proxy;
    }
}