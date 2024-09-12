pragma solidity ^0.4.18;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
     
    uint256 c = a / b;
     
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract ReadOnlyToken {
    uint256 public totalSupply;
    function balanceOf(address who) public constant returns (uint256);
    function allowance(address owner, address spender) public constant returns (uint256);
}

contract Upgradeable {
    address public target;
    event EventUpgrade(address target, address admin);

    modifier onlyAdmin() {
        checkAdmin();
        _;
    }

    function checkAdmin() internal;

    function upgrade(address _target) onlyAdmin public {
        verifyTargetState(_target);
        verifyState(_target);
        target = _target;
        EventUpgrade(_target, msg.sender);
    }

    function verifyTargetState(address testTarget) private {
        require(address(delegateGet(testTarget, "target()")) == target);
    }

    function verifyState(address testTarget) internal {

    }

    function delegateGet(address testTarget, string signature) internal returns (bytes32 result) {
        bytes4 targetCall = bytes4(keccak256(signature));
        assembly {
            let free := mload(0x40)
            mstore(free, targetCall)
            let retVal := delegatecall(gas, testTarget, free, 4, free, 32)
            result := mload(free)
        }
    }
}

contract TokenReceiver {
    function onTokenTransfer(address _from, uint256 _value, bytes _data) public;
}

contract Token is ReadOnlyToken {
  function transfer(address to, uint256 value) public returns (bool);
  function transferFrom(address from, address to, uint256 value) public returns (bool);
  function approve(address spender, uint256 value) public returns (bool);
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract NotifyingToken is Token {
    event Transfer(address indexed from, address indexed to, uint256 value, bytes data);
    function transferAndCall(address _to, uint256 _value, bytes _data) public returns (bool);
}

contract ReadOnlyTokenImpl is ReadOnlyToken {
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) internal allowed;

     
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

     
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}

contract TokenImpl is Token, ReadOnlyTokenImpl {
  using SafeMath for uint256;

   
  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);

     
    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    emitTransfer(msg.sender, _to, _value);
    return true;
  }

  function emitTransfer(address _from, address _to, uint256 _value) internal {
    Transfer(_from, _to, _value);
  }

   
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[_from]);
    require(_value <= allowed[_from][msg.sender]);

    balances[_from] = balances[_from].sub(_value);
    balances[_to] = balances[_to].add(_value);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
    emitTransfer(_from, _to, _value);
    return true;
  }

   
  function approve(address _spender, uint256 _value) public returns (bool) {
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

   
  function increaseApproval (address _spender, uint _addedValue) public returns (bool success) {
    allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
    Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }

  function decreaseApproval (address _spender, uint _subtractedValue) public returns (bool success) {
    uint oldValue = allowed[msg.sender][_spender];
    if (_subtractedValue > oldValue) {
      allowed[msg.sender][_spender] = 0;
    } else {
      allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
    }
    Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }

}

contract NotifyingTokenImpl is TokenImpl, NotifyingToken {
    function transfer(address _to, uint256 _value, bytes _data) public returns (bool) {
        return transferAndCall(_to, _value, _data);
    }

    function transferAndCall(address _to, uint256 _value, bytes _data) public returns (bool) {
        require(_to != address(0));
        require(_value <= balances[msg.sender]);

         
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emitTransferWithData(msg.sender, _to, _value, _data);
        TokenReceiver(_to).onTokenTransfer(msg.sender, _value, _data);
        return true;
    }

    function emitTransfer(address _from, address _to, uint256 _value) internal {
        emitTransferWithData(_from, _to, _value, "");
    }

    function emitTransferWithData(address _from, address _to, uint256 _value, bytes _data) internal {
        Transfer(_from, _to, _value, _data);
        Transfer(_from, _to, _value);
    }
}

contract ExternalToken is NotifyingTokenImpl {
    event Mint(address indexed to, uint256 value, bytes data);
    event Burn(address indexed burner, uint256 value, bytes data);

    modifier onlyMinter() {
        checkMinter();
        _;
    }

    function checkMinter() internal;

    function mint(address _to, uint256 _value, bytes _mintData) onlyMinter public returns (bool) {
        _mint(_to, _value, _mintData);
        emitTransferWithData(0x0, _to, _value, "");
        return true;
    }

    function mintAndCall(address _to, uint256 _value, bytes _mintData, bytes _data) onlyMinter public returns (bool) {
        _mint(_to, _value, _mintData);
        emitTransferWithData(0x0, _to, _value, _data);
        TokenReceiver(_to).onTokenTransfer(0x0, _value, _data);
        return true;
    }

    function _mint(address _to, uint256 _value, bytes _data) private {
        totalSupply = totalSupply.add(_value);
        balances[_to] = balances[_to].add(_value);
        Mint(_to, _value, _data);
    }

    function burn(uint256 _value, bytes _data) public {
        require(_value > 0);
        require(_value <= balances[msg.sender]);
        checkBurnData(_value, _data);

        address burner = msg.sender;
        balances[burner] = balances[burner].sub(_value);
        totalSupply = totalSupply.sub(_value);
        Burn(burner, _value, _data);
    }

    function checkBurnData(uint256 _value, bytes _data) internal {

    }
}

contract BitcoinToken is Upgradeable, ExternalToken {
    string public constant name = "Bitcoin";
    string public constant symbol = "BTCT";
    uint8 public constant decimals = 8;

    address public constant admin = 0x10a44fF9805c23f559d9c9f783091398CE54A556;
    address public constant minter1 = 0x884FFccB29d5aba8c94509663595F1dBF823dCC9;
    address public constant minter2 = 0x5aCC33B4318575581a80522B2e57D1d09e5eC111;

    function checkMinter() internal {
        require(msg.sender == minter1 || msg.sender == minter2);
    }

    function checkAdmin() internal {
        require(msg.sender == admin);
    }

    function checkBurnData(uint256 _value, bytes _data) internal {
        require(_data.length == 20);
    }
}