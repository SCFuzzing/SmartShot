pragma solidity ^0.4.26;

contract test {
    
    int256 a = 0;
    int256 b = 0;
    int256 v = 0;
    
    function foo(int256 t) public payable{
        if (t<10){
        v = 2 * t;
        v = 2 * t + 1;
        b = 3 * t + 60;
        if(v == 13) {
        msg.sender.transfer(this.balance);
        }
    }
    	if (t > 20){
    	v = 5 * t;
        v = 5 * t + 10;
        if(v == 180) {
        msg.sender.transfer(this.balance);
        }
    }
    }
    
    function bar(uint256 k) public payable{
    	if (v == 11) {
    	if(now % 15 == 0) { // winner
            msg.sender.transfer(this.balance);
        }
    	}
    	
    }
    
}
