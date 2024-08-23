#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import shlex
import solcx
import logging
import eth_utils
import subprocess
import random
import requests

from web3 import Web3, HTTPProvider
from .settings import LOGGING_LEVEL

def initialize_logger(name):
    logger = logging.getLogger(name)
    logger.title = lambda *a: logger.info(*[bold(x) for x in a])
    logger_error = logger.error
    logger.error = lambda *a: logger_error(*[red(bold(x)) for x in a])
    logger_warning = logger.warning
    logger.warning = lambda *a: logger_warning(*[red(bold(x)) for x in a])
    logger.setLevel(level=LOGGING_LEVEL)
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    return logger

def bold(x):
    return "".join(['\033[1m', x, '\033[0m']) if isinstance(x, str) else x

def red(x):
    return "".join(['\033[91m', x, '\033[0m']) if isinstance(x, str) else x

def code_bool(value: bool):
    return str(int(value)).zfill(64)

def code_uint(value):
    return hex(value).replace("0x", "").zfill(64)

def code_int(value):
    return hex(value).replace("0x", "").zfill(64)

def code_address(value):
    return value.zfill(64)

def code_bytes(value):
    return value.ljust(64, "0")

def code_type(value, type):
    if type == "bool":
        return code_bool(value)
    elif type.startswith("uint"):
        return code_uint(value)
    elif type.startswith("int"):
        return code_int(value)
    elif type == "address":
        return code_address(value)
    elif type.startswith("bytes"):
        return code_bytes(value)
    else:
        raise Exception()

def run_command(cmd):
    FNULL = open(os.devnull, 'w')
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return p.communicate()[0]

def compile(solc_version, evm_version, source_code_file):
    out = None
    source_code = ""
    with open(source_code_file, 'r') as file:
        source_code = file.read()
    try:
        if not str(solc_version).startswith("v"):
            solc_version = "v"+str(solc_version.truncate())
        if not solc_version in solcx.get_installed_solc_versions():
            solcx.install_solc(solc_version)
        solcx.set_solc_version(solc_version, True)
        out = solcx.compile_standard({
            'language': 'Solidity',
            'sources': {source_code_file: {'content': source_code}},
            'settings': {
                # "optimizer": {
                #     "enabled": True,
                #     "runs": 200
                # },
                "evmVersion": evm_version,
                "outputSelection": {
                    source_code_file: {
                        "*":
                            [
                                "abi",
                                "evm.deployedBytecode",
                                "evm.bytecode.object",
                                "evm.legacyAssembly",
                            ],
                    }
                }
            }
        }, allow_paths='.')
    except Exception as e:
        print("Error: Solidity compilation failed!")
        print(e.message)
    return out

def get_interface_from_abi(abi):
    interface = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            interface[hash] = function_inputs
        elif field['type'] == 'constructor':
            function_inputs = []
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
            interface['constructor'] = function_inputs
    if not "fallback" in interface:
        interface["fallback"] = []
    return interface

def get_function_signature_mapping(abi):
    mapping = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            mapping[hash] = signature
    if not "fallback" in mapping:
        mapping["fallback"] = "fallback"
    return mapping

def remove_swarm_hash(bytecode):
    if isinstance(bytecode, str):
        if bytecode.endswith("0029"):
            bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)
        if bytecode.endswith("0033"):
            bytecode = re.sub(r"5056fe.*?0033$", "5056", bytecode)
    return bytecode

def get_pcs_and_jumpis(bytecode):
    bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))
    i = 0
    pcs = []
    jumpis = []
    while i < len(bytecode):
        opcode = bytecode[i]
        pcs.append(i)
        if opcode == 87: # JUMPI
            jumpis.append(hex(i))
        if opcode >= 96 and opcode <= 127: # PUSH
            size = opcode - 96 + 1
            i += size
        i += 1
    if len(pcs) == 0:
        pcs = [0]
    return (pcs, jumpis)

def convert_stack_value_to_int(stack_value):
    if stack_value[0] == int:
        return stack_value[1]
    elif stack_value[0] == bytes:
        return int.from_bytes(stack_value[1], "big")
    else:
        raise Exception("Error: Cannot convert stack value to int. Unknown type: " + str(stack_value[0]))

def convert_stack_value_to_hex(stack_value):
    if stack_value[0] == int:
        return hex(stack_value[1]).replace("0x", "").zfill(64)
    elif stack_value[0] == bytes:
        return stack_value[1].hex().zfill(64)
    else:
        raise Exception("Error: Cannot convert stack value to hex. Unknown type: " + str(stack_value[0]))

def is_fixed(value):
    return isinstance(value, int)

def split_len(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]

def print_individual_solution_as_transaction(logger, individual_solution, color="", function_signature_mapping={}, transaction_index=None):
    for index, input in enumerate(individual_solution):
        transaction = input["transaction"]
        if not transaction["to"] == None:
            if transaction["data"].startswith("0x"):
                hash = transaction["data"][0:10]
            else:
                hash = transaction["data"][0:8]
            if len(individual_solution) == 1 or (transaction_index != None and transaction_index == 0):
                if hash in function_signature_mapping:
                    logger.title(color+"Transaction - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color+"Transaction:")
            else:
                if hash in function_signature_mapping:
                    logger.title(color+"Transaction " + str(index + 1) + " - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color+"Transaction " + str(index + 1) + ":")
            logger.title(color+"-----------------------------------------------------")
            logger.title(color+"From:      " + transaction["from"])
            logger.title(color+"To:        " + str(transaction["to"]))
            logger.title(color+"Value:     " + str(transaction["value"]) + " Wei")
            logger.title(color+"Gas Limit: " + str(transaction["gaslimit"]))
            i = 0
            for data in split_len("0x" + transaction["data"].replace("0x", ""), 42):
                if i == 0:
                    logger.title(color+"Input:     " + str(data))
                else:
                    logger.title(color+"           " + str(data))
                i += 1
            logger.title(color+"-----------------------------------------------------")
            if transaction_index != None and index + 1 > transaction_index:
                break

def normalize_32_byte_hex_address(value):
    as_bytes = eth_utils.to_bytes(hexstr=value)
    return eth_utils.to_normalized_address(as_bytes[-20:])

def get_onchain_status(_address, _block_number, chain, logger):
    color = "\u001b[34m"
    # Replace with your Alchemy API key:
    apiKey = "your-api-key"
    url = 'https://eth-mainnet.g.alchemy.com/v2/'+apiKey

    address = Web3.toChecksumAddress(_address)

    w3 = Web3(Web3.HTTPProvider(url))

    # block number given
    if _block_number:
        block_number = int(_block_number)
    
    else:
        # get logs by address
        try:
            logs = w3.eth.getLogs({
            'fromBlock': "earliest", 
            'toBlock': "latest",
                'address': address
            })
        except ValueError as e:
            pattern = r'\[(.*?)\]'
            matches = re.findall(pattern, str(e))
            match = matches[0]
            start = int(match.split(",")[0].strip(), 16)
            end = int(match.split(",")[1].strip(), 16)
            logger.title(color+f"Found Too Many Events, Requesting from {start} to {end}")
            logs = w3.eth.getLogs({
            'fromBlock': start, 
            'toBlock': end,
            'address': address
            })

        if logs:
            random.shuffle(logs)
            block_number = logs[0]["blockNumber"]

            logger.title(color+f"Found {len(logs)} Events, Choosing Block Number {block_number}")

        # no log, get current blocknumber
        else:
            payload = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_blockNumber"
            }
            headers = {
                "accept": "application/json",
                "content-type": "application/json"
            }

            response = requests.post(url, json=payload, headers=headers)

            block_number = int(response.json()["result"], 16)

            logger.title(color+f"No Event Found, Choosing Current Block Number {block_number}")

    # get timestamp/gas_limit/difficulty/blockhash/coinbase by blocknumber
    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [hex(block_number), True]
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers)

    timestamp = int(response.json()["result"]["timestamp"], 16)
    gas_limit = int(response.json()["result"]["gasLimit"], 16)
    difficulty = int(response.json()["result"]["difficulty"], 16)
    blockhash = response.json()["result"]["hash"]
    coinbase = response.json()["result"]["miner"]
    
    logger.title(color+f"Choosing Corresponding Timestamp {timestamp}")
    logger.title(color+f"Choosing Corresponding Gas Limit {gas_limit}")
    logger.title(color+f"Choosing Corresponding Difficulty {difficulty}")
    logger.title(color+f"Choosing Corresponding Blockhash {blockhash}")
    logger.title(color+f"Choosing Corresponding Coinbase {coinbase}")

    slot = 0
    last_empties = 0
    storage = {}
    while last_empties < 3:
        # get storage by blocknumber
        payload = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getStorageAt",
            "params": [address, hex(slot), hex(block_number)]
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }

        response = requests.post(url, json=payload, headers=headers)

        result = response.json()["result"]

        storage[slot] = result

        logger.title(color+f"Found Storage for Slot {slot}")
        
        if result == "0x" + "0" * 64:
            last_empties += 1
        else:
            last_empties = 0
        slot += 1

    return {"block_number": block_number, "timestamp": timestamp, "gas_limit": gas_limit, "difficulty": difficulty,
            "blockhash": blockhash, "coinbase": coinbase, "storage": storage}
