pragma solidity ^0.4.19;

contract BdpEntryPoint {
	address public ownerAddress;
	
	address public managerAddress;
	
	address public contracts;

	bool public setupCompleted = false;

	bytes8 public version;
	
	uint check = 0;
	
	function callproxy (uint data, uint _check)  external {
        //bytes memory data = msg.data;
        check = _check;
        if(check == 7){
        bool success = msg.sender.delegatecall(data);
        //msg.sender.call.value(msg.value)();
        
        require(success, "Delegatecall failed");
        }

    	}
    	
    	function BdpEntryPoint(address _contracts, bytes8 _version) public {
        ownerAddress = msg.sender;
        managerAddress = msg.sender;		
        contracts = _contracts;		
        setupCompleted = true;
        version = _version;
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

}
