/*
 * @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite
 * @author: Suhabe Bugrara
 * @vulnerable_at_lines: 18
 */

pragma solidity ^0.4.19;



contract ReentrancyDAO {
        mapping (address => uint) credit;
    uint balance;
    uint check = 0;

    function withdrawAll(uint _check) public {
    check = _check;
    if(check == 397){
        uint oCredit = credit[msg.sender];
        if (oCredit > 0) {
            balance -= oCredit;
            // <yes> <report> REENTRANCY
            bool callResult = msg.sender.call.value(oCredit)();
            require (callResult);
            credit[msg.sender] = 0;
        }
        }
    }

    function deposit() public payable {
        credit[msg.sender] += msg.value;
        balance += msg.value;
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
