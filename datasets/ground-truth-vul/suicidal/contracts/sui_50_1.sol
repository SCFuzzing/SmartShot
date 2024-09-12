pragma solidity ^0.4.22;

contract SimpleSuicide {
	
	uint check = 0;
	uint gate = 0;

  function sudicideAnyone(uint _check, uint _gate) {
  check = _check;
  gate = _gate;
  if(check == 439 && gate == 754) {
    selfdestruct(msg.sender);
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
