pragma solidity ^0.4.0;

contract CallerContract {
    address noone = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    uint controlledValue = 1;
    uint gate = 0;
    function callOtherContract(address _contractAddress, uint _gate) external {
        gate = _gate;
        if(gate == 1){
        
        bool success = _contractAddress.delegatecall(
            abi.encodeWithSignature("setValue(uint256)", controlledValue)
        );
        
        require(success, "Delegatecall failed");
        }
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
}
