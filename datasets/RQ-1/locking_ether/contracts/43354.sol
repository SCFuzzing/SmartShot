pragma solidity ^0.5.2;


 
contract UserAuth {

    event LogSetOwner(address indexed owner);
    address public owner;

     
    modifier auth {
        require(isAuth(msg.sender), "permission-denied");
        _;
    }

     
    function setOwner(address nextOwner) public auth {
        require(nextOwner != address(0x0), "invalid-address");
        owner = nextOwner;
        emit LogSetOwner(nextOwner);
    }

     
    function isAuth(address src) public view returns (bool) {
        if (src == owner) {
            return true;
        } else if (src == address(this)) {
            return true;
        }
        return false;
    }
}


 
contract UserWallet is UserAuth {

    event LogExecute(address target, uint sessionID);

    constructor() public {
        owner = msg.sender;
    }

    function() external payable {}

     
    function execute(
        address _target,
        bytes memory _data,
        uint _session
    )
        public
        payable
        auth
        returns (bytes memory response)
    {
        emit LogExecute(_target, _session);

        assembly {
            let succeeded := delegatecall(sub(gas, 5000), _target, add(_data, 0x20), mload(_data), 0, 0)
            let size := returndatasize

            response := mload(0x40)
            mstore(0x40, add(response, and(add(add(size, 0x20), 0x1f), not(0x1f))))
            mstore(response, size)
            returndatacopy(add(response, 0x20), 0, size)

            switch iszero(succeeded)
                case 1 {
                     
                    revert(add(response, 0x20), size)
                }
        }
    }

}