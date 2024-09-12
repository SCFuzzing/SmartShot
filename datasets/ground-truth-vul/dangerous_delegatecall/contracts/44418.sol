 
pragma solidity ^0.7.0;

interface AccountImplementations {
    function getImplementation(bytes4 _sig) external view returns (address);
}

 
contract InstaAccountV2 {

    AccountImplementations public immutable implementations;

    constructor(address _implementations) {
        implementations = AccountImplementations(_implementations);
    }

     
    function _delegate(address implementation) internal {
         
        assembly {
             
             
             
            calldatacopy(0, 0, calldatasize())

             
             
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

             
            returndatacopy(0, 0, returndatasize())

            switch result
             
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

     
    function _fallback(bytes4 _sig) internal {
        address _implementation = implementations.getImplementation(_sig);
        require(_implementation != address(0), "InstaAccountV2: Not able to find _implementation");
        _delegate(_implementation);
    }

     
    fallback () external payable {
        _fallback(msg.sig);
    }

     
    receive () external payable {
        if (msg.sig != 0x00000000) {
            _fallback(msg.sig);
        }
    }
}
