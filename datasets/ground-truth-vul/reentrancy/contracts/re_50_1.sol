/*
 * @source: https://ethernaut.zeppelin.solutions/level/0xf70706db003e94cfe4b5e27ffd891d5c81b39488
 * @author: Alejandro Santander
 * @vulnerable_at_lines: 24
 */

pragma solidity ^0.4.18;

contract Reentrance {

  mapping(address => uint) public balances;

  function donate(address _to) public payable {
    balances[_to] += msg.value;
  }

  function balanceOf(address _who) public view returns (uint balance) {
    return balances[_who];
  }

  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
      // <yes> <report> REENTRANCY
      if(msg.sender.call.value(_amount)()) {
        _amount;
      }
      balances[msg.sender] -= _amount;
    }
  }

  function() public payable {} 
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
