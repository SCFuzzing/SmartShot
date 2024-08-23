## SmartShot

**SmartShot is a mutable snapshot-based  fuzzer for smart contracts.**

![image](fuzzer/image/image.jpg)

### Requirements

1. #### web3

`web3` is a Python library that enables interaction with Ethereum nodes. It allows to send transactions, interact with smart contracts, and query blockchain data.

```shell
pip install web3 == 4.8.3
```

2. #### Solidity Compiler

`py-solc-x` is a wrapper around the Solidity compiler, `solc`, which is used to compile Solidity source code into bytecode and ABI.

```shell
pip install py-solc-x == 1.1.1
```

3. #### Z3 Prover

Download the source code of z3 and install.

```shell
python scripts/mk_make.py --python
cd build
make
make install
```

4. #### py-evm

`py-evm` is a Python implementation of the Ethereum Virtual Machine (EVM)

```shell
pip install py-evm==0.3.0a1
```

### Directory Structure

```
│
├── /fuzzer/
│   ├── main.py
│   ├── detectors/
│   ├── engine/
│   ├── evm/
│   ├── utils/
│   └── image/
│
├── /datasets/
│   ├── RQ1/
│   └── RQ2/
│
├── test.sol
├── requirements.txt
└── README.md
```

`main.py`: The main entry point of the application.

`detectors`: The test oracles used in SmartShot.

`engine`: The fuzzing engine implementation.

`evm`: The instrumented evm.

`utils`: Utility files used across the project.

`datasets`: The datasets used in our evaluations.

### Running Demo

#### CLI Command

```shell
cd fuzzer

python3 ./test.sol -c test --solc v0.4.26 --evm byzantium -g 80
```

`test.sol` is the sol file under test.

 `test` is the name of the contract to be fuzzed.

 `0.4.26` is the version of solidity compiler.

 `byzantium` is the desired EVM version. 

 `-g` indicates the number of generation. 

#### Fuzzing with On-chain Snapshots

```shell
cd fuzzer

python3 ./test.sol -c test --solc v0.4.26 --evm byzantium -g 80 -oc "contract_address" -bn "blocknumber"
```

`-oc` is used to specify the parameters for on-chain fuzzing, followed by the contract address on the blockchain.

`-bn` used to specify a block number, from which SmartShort obtains on-chain information to form the on-chain snapshot.

Note: before you use the on-chain option, please replace your `api key` in `fuzzer/utils/utils.py` in the function `get_onchain_status()`.
