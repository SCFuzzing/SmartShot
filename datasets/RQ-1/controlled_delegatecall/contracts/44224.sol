pragma solidity ^0.4.15;

 
contract ExperimentalProxy {
     

    bool public storageIsEternal;
    address public implementation;

     

     
    constructor(bool _storageIsEternal, address _implementation) public {
        storageIsEternal = _storageIsEternal;
        implementation = _implementation;
    }

     

     
    function () external payable {
        require(implementation != address(0), "Implementation cannot be the zero address.");  

         
        bool _storageIsEternal = storageIsEternal;
        bytes memory _data = msg.data;
        address _implementation = getImplementation(msg.sig, _data);

         
        bytes memory _retData;

         
        assembly {
             
            let _dataPtr := add(_data, 0x20)

             
            let _dataSize := mload(_data)

             
            let _result
            switch _storageIsEternal
            case 0 {  
                _result := call(gas, _implementation, callvalue, _dataPtr, _dataSize, 0, 0)
            }
            default {  
                _result := delegatecall(gas, _implementation, _dataPtr, _dataSize, 0, 0)
            }

             
            let _retSize := returndatasize

            let _retPtr := mload(0x40)  
            let _retDataPtr := add(_retPtr, 0x20)  

             
            mstore(_retPtr, _retSize)  
            returndatacopy(_retDataPtr, 0, _retSize)  

             
            switch _result
            case 0 {  
                revert(_retDataPtr, _retSize)
            }
            default {  
                _retData := _retPtr
            }
        }

         
        handleProxySuccess(msg.sig, _data, _retData);

         
        assembly {
            return(add(_retData, 0x20), mload(_retData))  
        }
    }

     

     
    function handleProxySuccess(bytes4 _sig, bytes _data, bytes _retData) private {}

     

     
    function getImplementation(bytes4 _sig, bytes _data) private view returns(address _implementation) { return implementation; }
}
