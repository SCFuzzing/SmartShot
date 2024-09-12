pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;
import "hardhat/console.sol";


 

interface DefaultImplementation {
    function version() external view returns(uint);
    function isAuth(address) external view returns(bool);
}

interface IndexInterface {
    function connectors(uint version) external view returns (address);
    function check(uint version) external view returns (address);
}

interface ConnectorsInterface {
    function isConnectors(string[] calldata connectorNames) external view returns (bool, address[] memory);
}

interface CheckInterface {
    function isOk() external view returns (bool);
}

contract InstaImplementationM2 {
    IndexInterface internal constant instaIndex = IndexInterface(0x2971AdFa57b20E5a416aE5a708A8655A9c74f723);

    address public constant connectorsM1 = address(0x5FbDB2315678afecb367f032d93F642f64180aa3);

    function decodeEvent(bytes memory response) internal pure returns (string memory _eventCode, bytes memory _eventParams) {
        (_eventCode, _eventParams) = abi.decode(response, (string, bytes));
    }

    event LogCast(
        address indexed origin,
        address indexed sender,
        uint value,
        string[] targetsNames,
        address[] targets,
        string[] eventNames,
        bytes[] eventParams
    );

    receive() external payable {}

      
    function spell(address _target, bytes memory _data) internal returns (bytes memory response) {
        require(_target != address(0), "target-invalid");
        assembly {
            let succeeded := delegatecall(gas(), _target, add(_data, 0x20), mload(_data), 0, 0)
            let size := returndatasize()
            
            response := mload(0x40)
            mstore(0x40, add(response, and(add(add(size, 0x20), 0x1f), not(0x1f))))
            mstore(response, size)
            returndatacopy(add(response, 0x20), 0, size)

            switch iszero(succeeded)
                case 1 {
                     
                    returndatacopy(0x00, 0x00, size)
                    revert(0x00, size)
                }
        }
    }

     
    function castWithFlashloan(
        string[] calldata _targetNames,
        bytes[] calldata _datas,
        address _origin
    )
    external
    payable 
    returns (bytes32)  
    {   

        DefaultImplementation defaultImplementation = DefaultImplementation(address(this));
        uint256 _length = _targetNames.length;

        require(defaultImplementation.isAuth(msg.sender) || msg.sender == address(instaIndex), "InstaImplementationM1: permission-denied");
        require(_length == _datas.length , "InstaImplementationM1: array-length-invalid");

        string[] memory eventNames = new string[](_length);
        bytes[] memory eventParams = new bytes[](_length);

        (bool isOk, address[] memory _targets) = ConnectorsInterface(connectorsM1).isConnectors(_targetNames);
        require(isOk, "1: not-connector");
        
        for (uint i = 0; i < _targets.length; i++) {
            bytes memory response = spell(_targets[i], _datas[i]);
            (eventNames[i], eventParams[i]) = decodeEvent(response);
        }
        
        emit LogCast(
            _origin,
            msg.sender,
            msg.value,
            _targetNames,
            _targets,
            eventNames,
            eventParams
        );
    }

}