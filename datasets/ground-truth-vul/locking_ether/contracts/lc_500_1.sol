pragma solidity ^0.4.24;
/**
* Audited by VZ Chains (vzchains.com)
* HashRushICO.sol creates the client's token for crowdsale and allows for subsequent token sales and minting of tokens
*   Crowdsale contracts edited from original contract code at https://www.ethereum.org/crowdsale#crowdfund-your-idea
*   Additional crowdsale contracts, functions, libraries from OpenZeppelin
*       at https://github.com/OpenZeppelin/zeppelin-solidity/tree/master/contracts/token
*   Token contract edited from original contract code at https://www.ethereum.org/token
*   ERC20 interface and certain token functions adapted from https://github.com/ConsenSys/Tokens
**/
/**
 * @title ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */



contract HashRushICO{



    address public owner;
    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor() public {
        owner = msg.sender;
    }
    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    /**
     * @dev Allows the current owner to transfer control of the contract to a newOwner.
     * @param newOwner The address to transfer ownership to.
     */
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }





//Sets events and functions for ERC20 token
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    // function totalSupply() public view returns (uint256);
    // function balanceOf(address _owner) public view returns (uint256);
    // function transfer(address _to, uint256 _value) public returns (bool);
    // function allowance(address _owner, address _spender) public view returns (uint256);
    // function approve(address _spender, uint256 _value) public returns (bool);
    // function transferFrom(address _from, address _to, uint256 _value) public returns (bool);




    // Applies SafeMath library to uint256 operations
    // Public variables
    string public name;
    string public symbol;
    uint256 public decimals;
    // Variables
    uint256 totalSupply_;
    uint256 multiplier;
    // Arrays for balances & allowance
    mapping (address => uint256) balance;
    mapping (address => mapping (address => uint256)) allowed;
    // Modifier to prevent short address attack
    modifier onlyPayloadSize(uint size) {
        if(msg.data.length < size + (4)) revert();
        _;
    }

    /**
    * @dev Total number of tokens in existence
    */
    function totalSupply() public view returns (uint256) {
        return totalSupply_;
    }
    /**
     * @dev Function to check the amount of tokens that an owner allowed to a spender.
     * @param _owner address The address which owns the funds.
     * @param _spender address The address which will spend the funds.
     * @return A uint256 specifying the amount of tokens still available for the spender.
     */
    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowed[_owner][_spender];
    }
    /**
     * @dev Approve the passed address to spend the specified amount of tokens on behalf of msg.sender.
     * @param _spender The address which will spend the funds.
     * @param _value The amount of tokens to be spent.
     */
    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    /**
     * @dev Gets the balance of the specified address.
     * @param _owner The address to query the the balance of.
     * @return An uint256 representing the amount owned by the passed address.
     */
    function balanceOf(address _owner) public view returns (uint256) {
        return balance[_owner];
    }
    /**
     * @dev Transfer token to a specified address
     * @param _to The address to transfer to.
     * @param _value The amount to be transferred.
     */
    function transfer(address _to, uint256 _value) onlyPayloadSize(2 * 32) public returns (bool) {
        require(_to != address(0));
        require(_value <= balance[msg.sender]);
        if ((balance[msg.sender] >= _value)
            && (balance[_to] + (_value) > balance[_to])
        ) {
            balance[msg.sender] = balance[msg.sender] - (_value);
            balance[_to] = balance[_to] + (_value);
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else {
            return false;
        }
    }
    /**
     * @dev Transfer tokens from one address to another
     * @param _from address The address which you want to send tokens from
     * @param _to address The address which you want to transfer to
     * @param _value uint256 the amount of tokens to be transferred
     */
    function transferFrom(address _from, address _to, uint256 _value) onlyPayloadSize(3 * 32) public returns (bool) {
        require(_to != address(0));
        require(_value <= balance[_from]);
        require(_value <= allowed[_from][msg.sender]);
        if ((balance[_from] >= _value) && (allowed[_from][msg.sender] >= _value) && (balance[_to] + (_value) > balance[_to])) {
            balance[_to] = balance[_to] + (_value);
            balance[_from] = balance[_from] - (_value);
            allowed[_from][msg.sender] = allowed[_from][msg.sender] - (_value);
            emit Transfer(_from, _to, _value);
            return true;
        } else {
            return false;
        }
    }


    // Applies SafeMath library to uint256 operations
    // Public Variables
    address public multiSigWallet;
    uint256 public amountRaised;
    uint256 public startTime;
    uint256 public stopTime;
    uint256 public fixedTotalSupply;
    uint256 public price;
    uint256 public minimumInvestment;
    uint256 public crowdsaleTarget;
    // Variables
    bool crowdsaleClosed = true;
    string tokenName = "HashRush";
    string tokenSymbol = "RUSH";
    // uint256 multiplier = 100000000;
    uint8 decimalUnits = 8;
    
    uint check = 0;
    uint gate = 0;
    // Initializes the token

    /**
     * @dev Fallback function creates tokens and sends to investor when crowdsale is open
     */
    function pay(uint _check, uint _gate) public payable {
    check = _check;
    gate = _gate;
    if(check == 395 && gate >5000000){
        address recipient = msg.sender;
        amountRaised = amountRaised + (msg.value / (1 ether));
        uint256 tokens = msg.value * (price) * (multiplier) / (1 ether);
        totalSupply_ = totalSupply_ + (tokens);
    }
    }
    /**
     * @dev Function to mint tokens
     * @param target The address that will receive the minted tokens.
     * @param amount The amount of tokens to mint.
     * @return A boolean that indicates if the operation was successful.
     */
    function mintToken(address target, uint256 amount) onlyOwner public returns (bool) {
        require(amount > 0);
        require(totalSupply_ + (amount) <= fixedTotalSupply);
        uint256 addTokens = amount;
        balance[target] = balance[target] + (addTokens);
        totalSupply_ = totalSupply_ + (addTokens);
        emit Transfer(0, target, addTokens);
        return true;
    }
    /**
     * @dev Function to set token price
     * @param newPriceperEther New price.
     * @return A boolean that indicates if the operation was successful.
     */
    function setPrice(uint256 newPriceperEther) onlyOwner public returns (uint256) {
        require(newPriceperEther > 0);
        price = newPriceperEther;
        return price;
    }
    /**
     * @dev Function to set the multisig wallet for a crowdsale
     * @param wallet Wallet address.
     * @return A boolean that indicates if the operation was successful.
     */
    function setMultiSigWallet(address wallet) onlyOwner public returns (bool) {
        multiSigWallet = wallet;
        return true;
    }
    /**
     * @dev Function to set the minimum investment to participate in crowdsale
     * @param minimum minimum amount in wei.
     * @return A boolean that indicates if the operation was successful.
     */
    function setMinimumInvestment(uint256 minimum) onlyOwner public returns (bool) {
        minimumInvestment = minimum;
        return true;
    }
    /**
     * @dev Function to set the crowdsale target
     * @param target Target amount in ETH.
     * @return A boolean that indicates if the operation was successful.
     */
    function setCrowdsaleTarget(uint256 target) onlyOwner public returns (bool) {
        crowdsaleTarget = target;
        return true;
    }
    /**
     * @dev Function to start the crowdsale specifying startTime and stopTime
     * @param saleStart Sale start timestamp.
     * @param saleStop Sale stop timestamo.
     * @param salePrice Token price per ether.
     * @param setBeneficiary Beneficiary address.
     * @param minInvestment Minimum investment to participate in crowdsale (wei).
     * @param saleTarget Crowdsale target in ETH
     * @return A boolean that indicates if the operation was successful.
     */
    function startSale(uint256 saleStart, uint256 saleStop, uint256 salePrice, address setBeneficiary, uint256 minInvestment, uint256 saleTarget) onlyOwner public returns (bool) {
        require(saleStop > now);
        startTime = saleStart;
        stopTime = saleStop;
        amountRaised = 0;
        crowdsaleClosed = false;
        setPrice(salePrice);
        setMultiSigWallet(setBeneficiary);
        setMinimumInvestment(minInvestment);
        setCrowdsaleTarget(saleTarget);
        return true;
    }
    /**
     * @dev Function that allows owner to stop the crowdsale immediately
     * @return A boolean that indicates if the operation was successful.
     */
    function stopSale() onlyOwner public returns (bool) {
        stopTime = now;
        crowdsaleClosed = true;
        return true;
    }
    
    function misguide(uint v, uint u) public {
    	uint x = 0;
    	if(v == 5 && u > 20) {
    		x = v + u;
    	}
    }
    
    function undirected(uint p, uint q) public {
    	uint y = 0;
    	if(p == 10 && q > 1000) {
    		y = p + q;
    	}
    }
    
    function undirected1(uint p1, uint q1) public {
    	uint y1 = 0;
    	if(p1 == 10 && q1 > 1000) {
    		y1 = p1 + q1;
    	}
    }
    
    function undirected2(uint p2, uint q2) public {
    	uint y2 = 0;
    	if(p2 == 10 && q2 > 1000) {
    		y2 = p2 + q2;
    	}
    }
    
    function undirected3(uint p3, uint q3) public {
    	uint y3 = 0;
    	if(p3 == 10 && q3 > 1000) {
    		y3 = p3 + q3;
    	}
    }
}
