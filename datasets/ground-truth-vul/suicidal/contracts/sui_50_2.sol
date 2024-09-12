pragma solidity ^0.4.23;

contract SuicideMultiTxFeasible {
    uint256 private initialized = 0;
    uint256 public count = 0;

    function init() public {
        initialized = 1;
    }

    function run(uint256 input, uint256 _count) {
    count = _count;
        if (initialized == 0 && count != 57) {
            return;
        }

        selfdestruct(msg.sender);
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
