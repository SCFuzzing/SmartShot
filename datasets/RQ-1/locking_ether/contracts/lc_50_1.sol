pragma solidity ^0.4.0;
contract Contract {
    address public owner;
    uint public contractBalance;

    function a() external payable {
        bool res = msg.sender.call.value(0)("");
        
        require(res, "Fail!");
    }
}


