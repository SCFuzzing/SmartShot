#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import psutil
import random
import numpy as np

from engine.environment import FuzzingEnvironment
from engine.plugin_interfaces import OnTheFlyAnalysis

from engine.fitness import fitness_function

from utils.utils import initialize_logger, convert_stack_value_to_int, convert_stack_value_to_hex, normalize_32_byte_hex_address, get_function_signature_mapping
from eth._utils.address import force_bytes_to_address
from eth_utils import to_hex, to_int, int_to_big_endian, encode_hex, ValidationError, to_canonical_address, to_normalized_address

from z3 import *
# from z3 import simplify, BitVec, BitVecVal, Not, Optimize, sat, unsat, unknown, is_expr
from z3.z3util import get_vars

from utils import settings

class ExecutionTraceAnalyzer(OnTheFlyAnalysis):
    def __init__(self, fuzzing_environment: FuzzingEnvironment, onchain_status) -> None:
        self.logger = initialize_logger("Analysis")
        self.env = fuzzing_environment
        self.symbolic_execution_count = 0
        self.env.onchain_status = onchain_status

    def setup(self, ng, engine):
        pass

    def execute(self, population, engine):
        self.env.memoized_fitness.clear()
        self.env.memoized_storage.clear()
        self.env.memoized_symbolic_execution.clear()
        self.env.individual_branches.clear()

        """from utils.utils import get_function_signature_mapping
        m = get_function_signature_mapping(self.env.abi)

        for i in population:
            a = [c["arguments"] for c in i.chromosome]
            b = []
            for j in a:
                arg = j[0]
                if arg in m:
                    b.append(m[arg]+" "+j[0])
                else:
                    b.append(arg)
            print(b)"""


        executed_individuals = dict()
        for i, individual in enumerate(population.individuals):
            if individual.hash in executed_individuals and not individual.snapshot:
                population.individuals[i] = executed_individuals[individual.hash]
                continue

            # snapshot-restoring individual deployment
            saved_storage = {}
            if individual.snapshot:
                self.env.instrumented_evm.create_snapshot()
                if self.env.instrumented_evm.snapshot["storage"].keys():
                    contract = list(self.env.instrumented_evm.snapshot["storage"].keys())[0]
                    # save the current storage
                    for storage_slot in individual.snapshot["snapshot"][0]:
                        saved_storage[storage_slot] = self.env.instrumented_evm.vm.state._account_db.get_storage(contract, storage_slot)
                    # deploy the snapshot storage       
                        self.env.instrumented_evm.vm.state._account_db.set_storage(contract, storage_slot, individual.snapshot["snapshot"][0][storage_slot])
                    self.env.instrumented_evm.vm.state._account_db.set_storage(contract, individual.snapshot["slot"], individual.snapshot["value"])
                    # last_used_var update
                    self.env.last_used_var = individual.snapshot
                    key = "_".join(("storage", str(individual.snapshot["slot"])))
                    self.env.solved_vars_used[key] += 1

            self.execution_function(individual, self.env)
            executed_individuals[individual.hash] = individual

            if individual.snapshot and saved_storage:
                # restore the storage
                for storage_slot in saved_storage:
                    self.env.instrumented_evm.vm.state._account_db.set_storage(contract, storage_slot, saved_storage[storage_slot])
                # remove the snapshot
                key = "_".join(("storage", str(individual.snapshot["slot"])))
                self.env.snapshot_reserved[key].pop(0)

        executed_individuals.clear()

        # Update statistic variables.
        engine._update_statvars()

    def register_step(self, g, population, engine):
        # onchain status deployment
        if g == -1 and self.env.onchain_status and self.env.instrumented_evm.snapshot["storage"].keys():
            contract = list(self.env.instrumented_evm.snapshot["storage"].keys())[0]
            for i in self.env.onchain_status["storage"]:
                if self.env.onchain_status["storage"][i].startswith("0x"+"0"*56) and self.env.onchain_status["storage"][i] != "0x"+"0"*64:
                    self.env.instrumented_evm.vm.state._account_db.set_storage(contract, i, int(self.env.onchain_status["storage"][i][26:], 16))
            color = "\u001b[34m"
            self.logger.title(color+"Storage Deployed")        

        self.execute(population, engine)

        code_coverage_percentage = 0
        if len(self.env.overall_pcs) > 0:
            code_coverage_percentage = (len(self.env.code_coverage) / len(self.env.overall_pcs)) * 100

        branch_coverage = 0
        for pc in self.env.visited_branches:
            branch_coverage += len(self.env.visited_branches[pc])
        branch_coverage_percentage = 0
        if len(self.env.overall_jumpis) > 0:
            branch_coverage_percentage = (branch_coverage / (len(self.env.overall_jumpis) * 2)) * 100

        msg = 'Generation number {} \t Code coverage: {:.2f}% ({}/{}) \t Branch coverage: {:.2f}% ({}/{}) \t ' \
              'Transactions: {} ({} unique)   \t Time: {}'.format(
            g + 1, code_coverage_percentage, len(self.env.code_coverage), len(self.env.overall_pcs),
            branch_coverage_percentage, branch_coverage, len(self.env.overall_jumpis) * 2, self.env.nr_of_transactions, len(self.env.unique_individuals),
            time.time() - self.env.execution_begin)
        self.logger.title(msg)

        # Save to results
        if "generations" not in self.env.results:
            self.env.results["generations"] = []

        self.env.results["generations"].append({
            "generation": g + 1,
            "time": time.time() - self.env.execution_begin,
            "total_transactions": self.env.nr_of_transactions,
            "unique_transactions": len(self.env.unique_individuals),
            "code_coverage": code_coverage_percentage,
            "branch_coverage": branch_coverage_percentage
        })

        if len(self.env.code_coverage) == self.env.previous_code_coverage_length:
            self.symbolic_execution(population.indv_generator)
            if self.symbolic_execution_count == settings.MAX_SYMBOLIC_EXECUTION:
                del population.individuals[:]
                population.init()
                self.logger.debug("Resetting population...")
                self.execute(population, engine)
                self.symbolic_execution_count = 0
            self.symbolic_execution_count += 1
        else:
            self.symbolic_execution_count = 0

        if self.env.taint_counter:
            self.env.taint_counter -= 1

        self.env.previous_code_coverage_length = len(self.env.code_coverage)

        return self.env.snapshot_reserved

    def collect_constraints(self, instruction, critical_jumpi_this_transaction, jumpi_this_transaction):
        # check if this JUMPI path and this op has been traversed        
        if (str(jumpi_this_transaction), instruction["pc"]) not in self.env.jumpi_path:
            self.env.jumpi_path.add((str(jumpi_this_transaction), instruction["pc"]))

            if critical_jumpi_this_transaction:
                jumpi_pc, jumpi_condition = critical_jumpi_this_transaction[-1]
                expression = self.env.visited_branches[jumpi_pc][jumpi_condition]["expression"]

                # key: the constraints that involve timestamp/blocknumber/call
                # value: a dict which:
                # key: JUMPI path that this transaction traverses
                # value: a tuple, the constraints of this path(i.e. expression)
                if str(expression).find("timestamp") != -1:
                    self.env.path_constraint["timestamp"][str(jumpi_this_transaction)] = expression
                if str(expression).find("blocknumber") != -1:
                    self.env.path_constraint["blocknumber"][str(jumpi_this_transaction)] = expression
        
                storages = []
                for storage in self.env.symbolic_taint_analyzer.storage.items():
                    for taint_slot, taint_value in storage[1].items():
                        storages.append(("_".join(["storage", str(int(taint_slot, 16))]), taint_value))

                        # key: JUMPI path that this transaction traverses
                        # value: a tuple which contains current analyzed tainted storage and its expression
                        # as for the same JUMPIs traversed, consider the constraints identical
                        self.env.tainted_storage[str(jumpi_this_transaction)] = (storages, expression)

    def take_snapshot(self, _type, _type_key, individual, transaction_index, storage_snapshot):
        self.env.instrumented_evm.create_snapshot()
        for contract in self.env.instrumented_evm.snapshot["storage"]:
            key = "_".join((_type, str(_type_key)))

            if key not in self.env.constraint_snapshot:
                self.env.constraint_snapshot[key] = []

            self.env.constraint_snapshot[key].append((storage_snapshot, individual, self.env.tainted_storage, 
                                                      self.env.instrumented_evm.vm.state.timestamp, 
                                                      self.env.instrumented_evm.vm.state.block_number,
                                                      transaction_index))
    
    def restore_snapshot(self, _type, _type_key):
        self.env.instrumented_evm.create_snapshot()

        key = "_".join((_type, str(_type_key)))

        if _type == "storage" and self.env.instrumented_evm.snapshot["storage"].keys():

            contract = list(self.env.instrumented_evm.snapshot["storage"].keys())[0]
            
            if not self.env.solved_vars.get(key):
                self.env.solved_vars[key] = []
            
            if not self.env.solved_vars_used.get(key):
                self.env.solved_vars_used[key] = 0
            
            if not self.env.snapshot_reserved.get(key):
                self.env.snapshot_reserved[key] = []
            
            if len(self.env.solved_vars[key]) <= self.env.solved_vars_used[key] and not self.env.snapshot_reserved.get(key):

                if key in self.env.constraint_snapshot:
                    vars = [var for jumpi_path, var in self.env.constraint_snapshot[key][-1][2].items()]
                    var = random.choice(vars)
                    calldataload = False
                    
                    if var[1]:
                        for exp in var[1]:
                            self.env.s.add(exp)
                            if str(exp).find("calldataload") != -1:
                                calldataload = True
                    
                    if calldataload:
                        for v in var[0]:
                            x = BitVec(v[0], 256)                    

                            # suppose the value of each var is a single expression
                            try:
                                self.env.s.add(x == v[1][0])
                            except:
                                pass

                        self.vars_add_constraints(self.env.s)

                        self.env.s.push()

                        if self.env.s.check() == sat:

                            for i in range(20):
                                self.env.s.check()
                                model = self.env.s.model()
                                self.env.solved_vars[key].append(dict())
                                calldataload_solved = False
                                
                                for result in model:
                                    if str(result) == key:
                                        self.env.solved_vars[key][-1]["value"] = model[result].as_long()
                                        self.env.solved_vars[key][-1]["snapshot"] = self.env.constraint_snapshot[key][-1]
                                        self.env.solved_vars[key][-1]["slot"] = _type_key

                                    elif str(result).startswith("calldataload"):
                                        self.env.solved_vars[key][-1][str(result)] = model[result].as_long()
                                        calldataload_solved = True
                                
                                if "value" not in self.env.solved_vars[key][-1]:
                                    self.env.solved_vars[key].pop()
                                
                                elif not calldataload_solved:
                                    # default 0
                                    self.env.solved_vars[key][-1]["calldataload_0_0"] = 0            
            
            if not self.env.snapshot_reserved[key]:
                for snapshot in range(5):
                    number_of_snapshots = len(self.env.snapshot_reserved[key])
                    if len(self.env.solved_vars[key]) > self.env.solved_vars_used[key] + number_of_snapshots:
                        self.env.snapshot_reserved[key].append(
                            self.env.solved_vars[key][self.env.solved_vars_used[key] + number_of_snapshots])
                    else:
                        break
        
        elif _type in ("timestamp", "blocknumber"):

            if not os.path.isfile(f"./mutation/mutated_{_type}.txt") and self.env.path_constraint[_type]:
                
                vars = [var for jumpi_path, var in self.env.path_constraint[_type].items()]
                var = random.choice(vars)
                
                ready_vars = []

                if var:
                    for exp in var:
                        self.env.s.add(exp)

                self.vars_add_constraints(self.env.s)
                
                self.env.s.push()

                for i in range(100):

                    if self.env.s.check() == sat:
                        model = self.env.s.model()
                        for result in model:
                            if str(result) == key:

                                ready_vars.append(str(model[result].as_long()) + "\n")
                
                if ready_vars:
                    with open(f"./mutation/mutated_{_type}.txt", "w+") as f:
                        f.writelines(ready_vars)  


        elif _type == "call":
            if not os.path.isfile(f"./mutation/mutated_{key}.txt"):
                ready_vars = []                  

                for i in range(100):
                    call_return = str(random.choice((0, 1)))
                    memory_sigma = random.choice((10, 10, 10, 100, 100, 1000, 10 ** 4, 10 **5, 10 ** 7, 10 ** 9, 10 ** 15))
                    memory = str(round(abs(np.random.normal(0, memory_sigma, 1)[0])))

                    ready_vars.append(call_return + " " + memory + "\n")             

                if ready_vars:
                    with open(f"./mutation/mutated_{key}.txt", "w+") as f:
                        f.writelines(ready_vars)

        
        self.env.s.reset()
    
    def vars_add_constraints(self, solver):
        vars = set()

        for c in solver.assertions():
            vars.update(z3.z3util.get_vars(c))
        
        for var in vars:
            if str(var).startswith("timestamp"):
                solver.add(ULT(var, 1715590184))
            
            elif str(var).startswith("blocknumber"):
                solver.add(ULT(var, 19871957))
            
            else:
                ceiling_bit = random.choice((10 ** 4, 10 ** 6, 10 ** 8, 10 ** 12, 10 ** 24))
                solver.add(ULT(var, ceiling_bit))


    def execution_function(self, indv, env: FuzzingEnvironment):
        env.unique_individuals.add(indv.hash)

        # Initialize metric
        branches = {}
        indv.data_dependencies = []
        contract_address = None

        env.detector_executor.initialize_detectors()

        for transaction_index, test in enumerate(indv.solution):

            transaction = test["transaction"]

            _function_hash = transaction["data"][:10] if transaction["data"].startswith("0x") else transaction["data"][:8]
            _function_hash = "fallback" if _function_hash == '' else _function_hash
            _array_size_indexes = dict()

            if transaction["to"] is None and contract_address is not None:
                transaction["to"] = contract_address

            if transaction["to"] is None:
                continue

            try:
                result = env.instrumented_evm.deploy_transaction(test)
            except ValidationError as e:
                self.logger.error("Validation error in %s : %s (ignoring for now)", indv.hash, e)
                continue

            if not result.is_error and transaction["to"] == b'':
                contract_address = encode_hex(result.msg.storage_address)
                self.logger.debug("(%s - %d) Contract deployed at %s", indv.hash, transaction_index, contract_address)

            for child_computation in result.children:
                if child_computation.msg.to not in env.other_contracts:
                    continue
                if child_computation.msg.to not in env.children_code_coverage:
                    env.children_code_coverage[child_computation.msg.to] = set()
                env.children_code_coverage[child_computation.msg.to].update([x["pc"] for x in child_computation.trace])

            env.nr_of_transactions += 1

            previous_instruction = None
            previous_branch = []
            previous_branch_expression = None
            previous_branch_address = None
            previous_call_address = None
            sha3 = {}

            # JUMPIs that involve expressions 
            critical_jumpi_this_transaction = []

            jumpi_this_transaction = []

            # if there is SSTORE to each state variable in this transaction
            sstore_this_transaction = {}

            # find the last SSTORE to each state variable before a JUMPI
            last_sstore = set()
            unique_storage = {}

            for i, instruction in enumerate(result.trace):
                if instruction["op"] == "SSTORE":
                    if instruction["stack"][-1][1] in sha3:
                        hash = instruction["stack"][-1][1]
                        while hash in sha3:
                            if len(sha3[hash]) == 64:
                                hash = sha3[hash][32:64]
                            else:
                                hash = sha3[hash]
                        storage_slot = int.from_bytes(hash, byteorder='big')
                    else:
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])
                    
                    unique_storage[storage_slot] = instruction["pc"]
                
                elif instruction["op"] == "JUMPI":
                    last_sstore.update(list(unique_storage.values()))
                    unique_storage = {}
            
            # before executing this transaction, take the snapshot and record the transaction index,
            # in case we need to replay this individual and abort the preceding transactions
            self.env.instrumented_evm.create_snapshot()
            if self.env.instrumented_evm.snapshot["storage"].keys():
                contract = list(self.env.instrumented_evm.snapshot["storage"].keys())[0]
                storage_snapshot_this_transaction = self.env.instrumented_evm.snapshot["storage"][contract]
            else:
                storage_snapshot_this_transaction = None

            for i, instruction in enumerate(result.trace):

                env.symbolic_taint_analyzer.propagate_taint(instruction, contract_address)

                env.detector_executor.run_detectors(previous_instruction, instruction, env.results["errors"],
                                                env.symbolic_taint_analyzer.get_tainted_record(index=-2), indv, env, previous_branch,
                                                transaction_index)

                # If constructor, we don't have to take into account the constructor inputs because they will be part of the
                # state. We don't have to compute the code coverage, because the code is not the deployed one. We don't need
                # to compute the cfg because we are on a different code. We actlually don't need analyzing its traces.
                try:
                    if indv.chromosome[transaction_index]["arguments"][0] == "constructor":
                        continue
                except:
                    self.env.taint_counter = 20
                    continue

                # Code coverage
                env.code_coverage.add(hex(instruction["pc"]))

                # Dynamically build control flow graph
                if env.cfg:
                    env.cfg.execute(instruction["pc"], instruction["stack"], instruction["op"], env.visited_branches,
                                    env.results["errors"].keys())

                if previous_instruction and previous_instruction["op"] == "SHA3":
                    sha3[instruction["stack"][-1][1]] = instruction["memory"]

                elif previous_instruction and previous_instruction["op"] == "ADD":
                    if previous_instruction["stack"][-1][1] in sha3:
                        sha3[instruction["stack"][-1][1]] = sha3[previous_instruction["stack"][-1][1]]
                    if previous_instruction["stack"][-2][1] in sha3:
                        sha3[instruction["stack"][-1][1]] = sha3[previous_instruction["stack"][-2][1]]

                if instruction["op"] == "JUMPI":
                    jumpi_pc = hex(instruction["pc"])
                    if jumpi_pc not in env.visited_branches:
                        env.visited_branches[jumpi_pc] = {}
                    if jumpi_pc not in branches:
                        branches[jumpi_pc] = dict()

                    destination = convert_stack_value_to_int(instruction["stack"][-1])
                    jumpi_condition = convert_stack_value_to_int(instruction["stack"][-2])

                    if jumpi_condition == 0:
                        # don't jump, but increase pc
                        branches[jumpi_pc][hex(destination)] = False
                        branches[jumpi_pc][hex(instruction["pc"] + 1)] = True
                    else:
                        # jump to destination
                        branches[jumpi_pc][hex(destination)] = True
                        branches[jumpi_pc][hex(instruction["pc"] + 1)] = False

                    env.visited_branches[jumpi_pc][jumpi_condition] = {}
                    env.visited_branches[jumpi_pc][jumpi_condition]["indv_hash"] = indv.hash
                    env.visited_branches[jumpi_pc][jumpi_condition]["chromosome"] = indv.chromosome
                    env.visited_branches[jumpi_pc][jumpi_condition]["transaction_index"] = transaction_index

                    tainted_record = env.symbolic_taint_analyzer.check_taint(instruction=instruction)
                    if tainted_record and tainted_record.stack and tainted_record.stack[-2]:
                        if jumpi_condition != 0:
                            previous_branch.append(tainted_record.stack[-2][0] != 0)
                        else:
                            previous_branch.append(tainted_record.stack[-2][0] == 0)
                        previous_branch_expression = previous_branch[-1]
                        env.visited_branches[jumpi_pc][jumpi_condition]["expression"] = previous_branch.copy()
                        critical_jumpi_this_transaction.append((jumpi_pc, jumpi_condition))
                    else:
                        env.visited_branches[jumpi_pc][jumpi_condition]["expression"] = None
                        previous_branch_expression = None

                    jumpi_this_transaction.append((jumpi_pc, jumpi_condition))
                    
                    previous_branch_address = jumpi_pc

                # Extract data dependencies (read-after-write)
                elif instruction["op"] == "SLOAD":
                    if instruction["stack"][-1][1] in sha3:
                        hash = instruction["stack"][-1][1]
                        while hash in sha3:
                            if len(sha3[hash]) == 64:
                                hash = sha3[hash][32:64]
                            else:
                                hash = sha3[hash]
                        storage_slot = int.from_bytes(hash, byteorder='big')
                    else:
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])

                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                    if _function_hash not in self.env.data_dependencies:
                        self.env.data_dependencies[_function_hash] = {"read": set(), "write": set()}
                    self.env.data_dependencies[_function_hash]["read"].add(storage_slot)

                    if not self.env.taint_counter:
                        taint = BitVec("_".join(["storage", str(storage_slot)]), 256)
                        env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                        key = "_".join(("storage", str(storage_slot)))
                    
                        if not indv.snapshot and not self.env.snapshot_reserved.get(key) \
                        and storage_slot not in sstore_this_transaction:
                            self.restore_snapshot("storage", storage_slot)

                elif instruction["op"] == "SSTORE":
                    if instruction["stack"][-1][1] in sha3:
                        hash = instruction["stack"][-1][1]
                        while hash in sha3:
                            if len(sha3[hash]) == 64:
                                hash = sha3[hash][32:64]
                            else:
                                hash = sha3[hash]
                        storage_slot = int.from_bytes(hash, byteorder='big')
                    else:
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])

                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                    if _function_hash not in self.env.data_dependencies:
                        self.env.data_dependencies[_function_hash] = {"read": set(), "write": set()}
                    self.env.data_dependencies[_function_hash]["write"].add(storage_slot)

                    sstore_this_transaction[storage_slot] = True
                                
                    self.collect_constraints(instruction, critical_jumpi_this_transaction, jumpi_this_transaction)

                    # this SSTORE is the last SSTORE to this storage slot before a JUMPI

                    if instruction["pc"] in last_sstore and storage_snapshot_this_transaction:
                        self.take_snapshot("storage", storage_slot, indv, transaction_index, storage_snapshot_this_transaction)                           

                # If something goes wrong, we need to clean some pools
                elif instruction["op"] in ["REVERT", "INVALID", "ASSERTFAIL"]:
                    if previous_branch_expression is not None and is_expr(previous_branch_expression):
                        # Only remove from pool when you are sure which variable caused the exception
                        if len(get_vars(previous_branch_expression)) == 1:
                            for var in get_vars(previous_branch_expression):
                                _str_var = str(var)

                                if _str_var.startswith("calldataload_") or str(var).startswith("calldatacopy_"):
                                    _parameter_index = int(str(var).split("_")[-1])
                                    _transaction_index = int(str(var).split("_")[-2])
                                    _function_hash = indv.chromosome[_transaction_index]["arguments"][0]
                                    _argument = indv.chromosome[_transaction_index]["arguments"][_parameter_index + 1]
                                    indv.generator.remove_argument_from_pool(_function_hash, _parameter_index, _argument)

                                elif _str_var.startswith("callvalue_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _amount = transaction["value"]
                                    if _amount == 0 or _amount == 1:
                                        indv.generator.remove_amount_from_pool(_function_hash, _amount)

                                elif _str_var.startswith("caller_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _caller = transaction["from"]
                                    indv.generator.remove_account_from_pool(_function_hash, _caller)

                                elif _str_var.startswith("gas_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _gas_limit = indv.chromosome[transaction_index]["gaslimit"]
                                    indv.generator.remove_gaslimit_from_pool(_function_hash, _gas_limit)

                                elif _str_var.startswith("blocknumber_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _blocknumber = indv.chromosome[transaction_index]["blocknumber"]
                                    indv.generator.remove_blocknumber_from_pool(_function_hash, _blocknumber)

                                elif _str_var.startswith("timestamp_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _timestamp = indv.chromosome[transaction_index]["timestamp"]
                                    indv.generator.remove_timestamp_from_pool(_function_hash, _timestamp)

                                elif _str_var.startswith("call_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _var_split = str(var).split("_")
                                    _address = to_normalized_address(_var_split[2])
                                    _result = int(_var_split[3], 16)
                                    indv.generator.remove_callresult_from_pool(_function_hash, _address, _result)

                                elif _str_var.startswith("extcodesize"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _var_split = str(var).split("_")
                                    _address = to_normalized_address(_var_split[2])
                                    _size = int(_var_split[3], 16)
                                    indv.generator.remove_extcodesize_from_pool(_function_hash, _address, _size)

                                elif _str_var.startswith("returndatasize"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _var_split = str(var).split("_")
                                    _address = to_normalized_address(_var_split[2])
                                    _size = int(_var_split[3], 16)
                                    indv.generator.remove_returndatasize_from_pool(_function_hash, _address, _size)

                elif instruction["op"] == "BALANCE":
                    taint = BitVec("_".join(["balance", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] in ["CALL", "STATICCALL"]:
                    _address_as_hex = to_hex(force_bytes_to_address(int_to_big_endian(convert_stack_value_to_int(result.trace[i]["stack"][-2]))))
                    if i + 1 < len(result.trace):
                        _result_as_hex = convert_stack_value_to_hex(result.trace[i + 1]["stack"][-1])
                    else:
                        _result_as_hex = ""
                    previous_call_address = _address_as_hex
                    call_type = "call"
                    if instruction["op"] == "STATICCALL":
                        call_type = "staticcall"
                    taint = BitVec("_".join([call_type, str(transaction_index), str(_address_as_hex), str(_result_as_hex), str(instruction["pc"])]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                    self.collect_constraints(instruction, critical_jumpi_this_transaction, jumpi_this_transaction)
                    if storage_snapshot_this_transaction:
                        self.take_snapshot("call", instruction["pc"], indv, transaction_index, storage_snapshot_this_transaction)
                    self.restore_snapshot("call", "_".join([str(_address_as_hex), str(instruction["pc"])]))

                elif instruction["op"] == "CALLER":
                    taint = BitVec("_".join(["caller", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "CALLDATALOAD":
                    input_index = convert_stack_value_to_int(instruction["stack"][-1])
                    if input_index > 0 and _function_hash in env.interface:
                        input_index = int((input_index - 4) / 32)
                        if input_index < len(env.interface[_function_hash]):
                            parameter_type = env.interface[_function_hash][input_index]
                            if '[' in parameter_type:
                                array_size_index = convert_stack_value_to_int(result.trace[i + 1]["stack"][-1]) / 32
                                _array_size_indexes[array_size_index] = input_index
                            elif "bytes" in parameter_type:
                                pass
                            else:
                                taint = BitVec("_".join(["calldataload",
                                                         str(transaction_index),
                                                         str(input_index)
                                                         ]), 256)
                                env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                        else:
                            if input_index in _array_size_indexes:
                                array_size = convert_stack_value_to_int(result.trace[i + 1]["stack"][-1])
                                taint = BitVec("_".join(["inputarraysize",
                                                         str(transaction_index),
                                                         str(_array_size_indexes[input_index])
                                                         ]), 256)
                                env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                            else:
                                pass

                elif instruction["op"] == "CALLDATACOPY":
                    destOffset = convert_stack_value_to_int(instruction["stack"][-1])
                    offset = convert_stack_value_to_int(instruction["stack"][-2])
                    array_start_index = (offset - 4) / 32
                    lenght = convert_stack_value_to_int(instruction["stack"][-3])

                    if array_start_index - 1 in _array_size_indexes:
                        taint = BitVec("_".join(["calldatacopy",
                                                 str(transaction_index),
                                                 str(_array_size_indexes[array_start_index - 1])
                                                 ]), 256)
                        env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                    else:
                        pass

                elif instruction["op"] == "CALLDATASIZE":
                    taint = BitVec("_".join(["calldatasize", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "CALLVALUE":
                    taint = BitVec("_".join(["callvalue", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "GAS":
                    taint = BitVec("_".join(["gas", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                # BLOCK Opcodes
                elif instruction["op"] == "BLOCKHASH":
                    taint = BitVec("_".join(["blockhash", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "COINBASE":
                    taint = BitVec("_".join(["coinbase", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "TIMESTAMP":
                    taint = BitVec("_".join(["timestamp", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                    self.collect_constraints(instruction, critical_jumpi_this_transaction, jumpi_this_transaction)
                    if storage_snapshot_this_transaction:                 
                        self.take_snapshot("timestamp", instruction["pc"], indv, transaction_index, storage_snapshot_this_transaction)
                    self.restore_snapshot("timestamp", transaction_index)                    

                elif instruction["op"] == "NUMBER":
                    taint = BitVec("_".join(["blocknumber", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                    self.collect_constraints(instruction, critical_jumpi_this_transaction, jumpi_this_transaction) 
                    if storage_snapshot_this_transaction:               
                        self.take_snapshot("blocknumber", instruction["pc"], indv, transaction_index, storage_snapshot_this_transaction)
                    self.restore_snapshot("blocknumber", transaction_index)

                elif instruction["op"] == "DIFFICULTY":
                    taint = BitVec("_".join(["difficulty", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "GASLIMIT":
                    taint = BitVec("_".join(["gaslimit", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "EXTCODESIZE":
                    _address_as_hex = to_hex(
                        force_bytes_to_address(int_to_big_endian(convert_stack_value_to_int(result.trace[i]["stack"][-1]))))
                    if i + 1 < len(result.trace):
                        _result_as_hex = convert_stack_value_to_hex(result.trace[i + 1]["stack"][-1])
                    else:
                        _result_as_hex = ""
                    taint = BitVec("_".join(["extcodesize", str(transaction_index), str(_address_as_hex), str(_result_as_hex)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "RETURNDATASIZE":
                    if previous_call_address:
                        if i + 1 < len(result.trace):
                            _size = convert_stack_value_to_int(result.trace[i + 1]["stack"][-1])
                        else:
                            _size = 0
                        taint = BitVec("_".join(["returndatasize", str(transaction_index), previous_call_address, str(_size)]), 256)
                        env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                previous_instruction = instruction

            env.symbolic_taint_analyzer.clear_callstack()

            if not result.is_error and not transaction["to"]:
                contract_address = encode_hex(result.msg.storage_address)

        env.individual_branches[indv.hash] = branches

        env.symbolic_taint_analyzer.clear_storage()
        env.instrumented_evm.restore_from_snapshot()

    def get_coverage_with_children(self, children_code_coverage, code_coverage):
        code_coverage = len(code_coverage)

        for child_cc in children_code_coverage:
            code_coverage += len(child_cc)
        return code_coverage

    def symbolic_execution(self, indv_generator):
        if not self.env.args.constraint_solving:
            return

        for index, pc in enumerate(self.env.visited_branches):
            self.logger.debug("b(%d) pc : %s - visited branches : %s", index, pc,
                               self.env.visited_branches[pc].keys())

            if len(self.env.visited_branches[pc]) != 1:
                continue

            branch, _d = next(iter(self.env.visited_branches[pc].items()))

            if not _d["expression"]:
                self.logger.debug("No expression for b(%d) pc : %s", index, pc)
                continue

            negated_branch = simplify(Not(_d["expression"][-1]))

            if negated_branch in self.env.memoized_symbolic_execution:
                continue

            self.env.solver.reset()
            for expression_index in range(len(_d["expression"]) - 1):
                expression = simplify(_d["expression"][expression_index])
                self.env.solver.add(expression)
            self.env.solver.add(negated_branch)

            if not self.env.taint_counter and self.env.tainted_storage:
                random_storage = random.choice(list(self.env.tainted_storage.items()))[1]
                
                storages, constraints = random_storage
                
                for storage_expression in storages:
                    x = BitVec(storage_expression[0], 256)                    

                    # suppose the value of each var is a single expression
                    try:
                        self.env.solver.add(x == storage_expression[1][0])
                    except:
                        pass

                if constraints:
                    for constraint in constraints:
                        self.env.solver.add(constraint)


            check = self.env.solver.check()

            if check == sat:
                model = self.env.solver.model()

                self.logger.debug("(%s) Symbolic Solution to branch %s: %s ", _d["indv_hash"], pc,
                                  "; ".join([str(x)+" ("+str(model[x])+")" for x in model]))

                for variable in model:
                    if str(variable).startswith("underflow"):
                        continue

                    var_split = str(variable).split("_")
                    transaction_index = int(var_split[1])

                    try:
                        if transaction_index >= len(_d["chromosome"]):
                            self.env.taint_counter = 20
                            break
                        
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        
                        if len(var_split) > 2:
                            parameter_index = int(var_split[2])
                            if parameter_index >= len(indv_generator.interface[_function_hash]):
                                self.env.taint_counter = 20
                                break
                    except:
                        self.env.taint_counter = 20
                        break

                    if str(variable).startswith("balance"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        opt = Optimize()
                        for expression_index in range(len(_d["expression"]) - 1):
                            opt.add(_d["expression"][expression_index])
                        opt.add(negated_branch)
                        check = opt.check()
                        if check == sat:
                            opt_model = opt.model()
                            balance = int(opt_model[variable].as_long())
                            if _d["chromosome"][transaction_index]["contract"]:
                                indv_generator.add_balance_to_pool(_function_hash, self.env.instrumented_evm.get_balance(
                                    to_canonical_address(_d["chromosome"][transaction_index]["contract"])))
                            indv_generator.add_balance_to_pool(_function_hash, balance)

                    elif str(variable).startswith("blocknumber"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        blocknumber = int(model[variable].as_long())
                        indv_generator.add_blocknumber_to_pool(_function_hash,
                                                               self.env.instrumented_evm.vm.state.block_number)
                        indv_generator.add_blocknumber_to_pool(_function_hash, blocknumber)

                    elif str(variable).startswith("call_") or str(variable).startswith("staticcall_"):
                        address = to_normalized_address(var_split[2])
                        old_result = int(var_split[3], 16)
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        new_result = 1 - old_result
                        indv_generator.add_callresult_to_pool(_function_hash, address, old_result)
                        indv_generator.add_callresult_to_pool(_function_hash, address, new_result)

                    elif str(variable).startswith("caller_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        if model[variable].as_long() > 8 and model[variable].as_long() < 2**160:
                            account_address = normalize_32_byte_hex_address("0x"+hex(model[variable].as_long()).replace("0x", "").zfill(40))
                            if not self.env.instrumented_evm.has_account(account_address):
                                self.env.instrumented_evm.restore_from_snapshot()
                                self.env.instrumented_evm.accounts.append(self.env.instrumented_evm.create_fake_account(account_address))
                                self.env.instrumented_evm.create_snapshot()
                            indv_generator.add_account_to_pool(_function_hash, _d["chromosome"][transaction_index]["account"])
                            indv_generator.add_account_to_pool(_function_hash, account_address)

                    elif str(variable).startswith("calldatacopy_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        parameter_index = int(var_split[2])
                        if "[" in indv_generator.interface[_function_hash][parameter_index]:
                            if indv_generator.interface[_function_hash][parameter_index].startswith("int"):
                                argument = model[variable].as_signed_long()
                            elif indv_generator.interface[_function_hash][parameter_index].startswith("address"):
                                try:
                                    _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                                    argument = normalize_32_byte_hex_address(hex(model[variable].as_long()))
                                    if not self.env.instrumented_evm.has_account(argument):
                                        self.env.instrumented_evm.restore_from_snapshot()
                                        self.env.instrumented_evm.accounts.append(self.env.instrumented_evm.create_fake_account(argument))
                                        self.env.instrumented_evm.create_snapshot()
                                except Exception as e:
                                    self.logger.error("(%s) [symbolic execution : calldatacopy ] %s", _function_hash,
                                                       e)
                                    continue
                            else:
                                argument = model[variable].as_long()
                            indv_generator.add_argument_to_pool(_function_hash, parameter_index, _d["chromosome"][transaction_index]["arguments"][parameter_index + 1])
                            indv_generator.add_argument_to_pool(_function_hash, parameter_index, argument)

                    elif str(variable).startswith("calldataload_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        parameter_index = int(var_split[2])
                        # TODO: THE SOLVER DOES NOT CONSIDER THE MAX SIZE OF THE VARIABLE
                        #   GENERATING LATER A eth_abi.exceptions.ValueOutOfBounds
                        if "[" in indv_generator.interface[_function_hash][parameter_index]:
                            if indv_generator.interface[_function_hash][parameter_index].startswith("int"):
                                argument = model[variable].as_signed_long()
                            elif indv_generator.interface[_function_hash][parameter_index].startswith("address"):
                                try:
                                    _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                                    argument = normalize_32_byte_hex_address(hex(model[variable].as_long()))
                                    if not self.env.instrumented_evm.has_account(argument):
                                        self.env.instrumented_evm.restore_from_snapshot()
                                        self.env.instrumented_evm.accounts.append(self.env.instrumented_evm.create_fake_account(argument))
                                        self.env.instrumented_evm.create_snapshot()
                                except Exception as e:
                                    self.logger.error("(%s) [symbolic execution : calldataload ] %s", _function_hash,
                                                       e)
                                    continue

                        elif indv_generator.interface[_function_hash][parameter_index].startswith("int"):
                            argument = model[variable].as_signed_long()

                        elif indv_generator.interface[_function_hash][parameter_index] == "address":
                            try:
                                _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                                argument = to_hex(
                                    force_bytes_to_address(int_to_big_endian(int(model[variable].as_long()))))
                                if not self.env.instrumented_evm.has_account(argument):
                                    self.env.instrumented_evm.restore_from_snapshot()
                                    self.env.instrumented_evm.accounts.append(self.env.instrumented_evm.create_fake_account(argument))
                                    self.env.instrumented_evm.create_snapshot()
                            except Exception as e:
                                self.logger.error("(%s) [symbolic execution : calldataload ] %s", _function_hash, e)
                                continue

                        elif indv_generator.interface[_function_hash][parameter_index] == "string":
                            argument = _d["chromosome"][transaction_index]["arguments"][parameter_index + 1]
                        elif indv_generator.interface[_function_hash][parameter_index].startswith("uint"):
                            argument = model[variable].as_long()
                            bits = 256
                            if indv_generator.interface[_function_hash][parameter_index] != "uint":
                                bits = int(indv_generator.interface[_function_hash][parameter_index].replace("uint", ""))
                            base = 1 << bits
                            argument %= base
                        else:
                            argument = model[variable].as_long()
                            self.env.solver.add(BitVec(str(variable), 256) != BitVecVal(0, 256))
                            for variable_2 in model:
                                if variable_2 != variable and str(variable_2).startswith("callvalue"):
                                    callvalue_index = int(str(variable_2).split("_")[1])
                                    self.env.solver.add(BitVec(str(variable_2), 256) == BitVecVal(int(_d["chromosome"][callvalue_index]["amount"]), 256))
                            check = self.env.solver.check()
                            if check == sat:
                                model = self.env.solver.model()
                                argument = model[variable].as_long()

                        indv_generator.add_argument_to_pool(_function_hash, parameter_index, _d["chromosome"][transaction_index]["arguments"][parameter_index + 1])
                        indv_generator.add_argument_to_pool(_function_hash, parameter_index, argument)

                    elif str(variable).startswith("callvalue_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        amount = model[variable].as_long()
                        if amount > settings.ACCOUNT_BALANCE:
                            amount = settings.ACCOUNT_BALANCE
                        indv_generator.remove_amount_from_pool(_function_hash, 0)
                        indv_generator.remove_amount_from_pool(_function_hash, 1)
                        indv_generator.add_amount_to_pool(_function_hash, _d["chromosome"][transaction_index]["amount"])
                        indv_generator.add_amount_to_pool(_function_hash, amount)

                    elif str(variable).startswith("gas_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        indv_generator.add_gaslimit_to_pool(_function_hash, _d["chromosome"][transaction_index]["gaslimit"])
                        indv_generator.add_gaslimit_to_pool(_function_hash, model[variable].as_long())

                    elif str(variable).startswith("inputarraysize"):
                        opt = Optimize()
                        for expression_index in range(len(_d["expression"]) - 1):
                            opt.add(_d["expression"][expression_index])
                        opt.add(negated_branch)
                        check = opt.check()
                        if check == sat:
                            opt_model = opt.model()
                            array_size = opt_model[variable].as_long()
                            _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                            parameter_index = int(var_split[2])
                            indv_generator.add_parameter_array_size(_function_hash, parameter_index, len(
                                _d["chromosome"][transaction_index]["arguments"][parameter_index + 1]))
                            indv_generator.add_parameter_array_size(_function_hash, parameter_index, array_size)

                    elif str(variable).startswith("timestamp"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        timestamp = int(model[variable].as_long())
                        indv_generator.add_timestamp_to_pool(_function_hash, self.env.instrumented_evm.vm.state.timestamp)
                        indv_generator.add_timestamp_to_pool(_function_hash, timestamp)

                    elif str(variable).startswith("calldatasize"):
                        pass

                    elif str(variable).startswith("extcodesize"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        _address = to_normalized_address(var_split[2])
                        indv_generator.add_extcodesize_to_pool(_function_hash, _address, int(var_split[3], 16))
                        indv_generator.add_extcodesize_to_pool(_function_hash, _address, int(model[variable].as_long()))

                    elif str(variable).startswith("returndatasize"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        _address = to_normalized_address(var_split[2])
                        _size = int(var_split[3], 16)
                        indv_generator.add_returndatasize_to_pool(_function_hash, _address, int(var_split[3], 16))
                        indv_generator.add_returndatasize_to_pool(_function_hash, _address, int(model[variable].as_long()))

                    elif str(variable).startswith("storage"):
                        pass
                    
                    else:
                        self.logger.warning("Unknown symbolic variable: %s ", str(variable))

            self.env.memoized_symbolic_execution[negated_branch] = True

    def finalize(self, population, engine):
        execution_end = time.time()
        execution_delta = execution_end - self.env.execution_begin

        self.logger.title("-----------------------------------------------------")
        msg = 'Number of generations: \t {}'.format(engine.current_generation + 1)
        self.logger.info(msg)
        msg = 'Number of transactions: \t {} ({} unique)'.format(self.env.nr_of_transactions, len(self.env.unique_individuals))
        self.logger.info(msg)
        msg = 'Transactions per second: \t {:.0f}'.format(self.env.nr_of_transactions / execution_delta)
        self.logger.info(msg)
        code_coverage_percentage = 0
        if len(self.env.overall_pcs) > 0:
            code_coverage_percentage = (len(self.env.code_coverage) / len(self.env.overall_pcs)) * 100
        msg = 'Total code coverage: \t {:.2f}% ({}/{})'.format(code_coverage_percentage,
                                                                len(self.env.code_coverage),
                                                                len(self.env.overall_pcs))
        self.logger.info(msg)
        branch_coverage = 0
        for pc in self.env.visited_branches:
            branch_coverage += len(self.env.visited_branches[pc])
        branch_coverage_percentage = 0
        if len(self.env.overall_jumpis) > 0:
            branch_coverage_percentage = (branch_coverage / (len(self.env.overall_jumpis) * 2)) * 100
        msg = 'Total branch coverage: \t {:.2f}% ({}/{})'.format(branch_coverage_percentage,
                                                                 branch_coverage, len(self.env.overall_jumpis) * 2)
        self.logger.info(msg)
        msg = 'Total execution time: \t {:.2f} seconds'.format(execution_delta)
        self.logger.info(msg)
        msg = 'Total memory consumption: \t {:.2f} MB'.format(psutil.Process(os.getpid()).memory_info().rss/1024/1024)
        self.logger.info(msg)

        # Save to results
        self.env.results["transactions"] = {"total": self.env.nr_of_transactions,
                                            "per_second": self.env.nr_of_transactions / execution_delta}
        self.env.results["code_coverage"] = {"percentage": code_coverage_percentage,
                                             "covered": len(self.env.code_coverage),
                                             "total": len(self.env.overall_pcs),
                                             "covered_with_children": self.get_coverage_with_children(
                                                 self.env.children_code_coverage,
                                                 self.env.code_coverage),
                                             "total_with_children": self.env.len_overall_pcs_with_children
                                             }
        self.env.results["branch_coverage"] = {"percentage": branch_coverage_percentage,
                                               "covered": branch_coverage,
                                               "total": len(self.env.overall_jumpis) * 2}
        self.env.results["execution_time"] = execution_delta
        self.env.results["memory_consumption"] = psutil.Process(os.getpid()).memory_info().rss/1024/1024
        self.env.results["address_under_test"] = self.env.population.indv_generator.contract
        self.env.results["seed"] = self.env.seed

        #  Write results to file
        if self.env.args.results:
            results = {}
            if self.env.args.results.lower().endswith(".json"):
                if os.path.exists(self.env.args.results):
                    with open(self.env.args.results, 'r') as file:
                        results = json.load(file)
                results[self.env.contract_name] = self.env.results
                with open(self.env.args.results, 'w') as file:
                    json.dump(results, file)
            else:
                if os.path.exists(self.env.args.results + '/' + os.path.splitext(os.path.basename(self.env.contract_name))[0] + '.json'):
                    with open(self.env.args.results + '/' + os.path.splitext(os.path.basename(self.env.contract_name))[0] + '.json', 'r') as file:
                        results = json.load(file)
                results[self.env.contract_name] = self.env.results
                with open(self.env.args.results + '/' + os.path.splitext(os.path.basename(self.env.contract_name))[0] + '.json', 'w') as file:
                    json.dump(results, file)

        diff = list(set(self.env.code_coverage).symmetric_difference(set([hex(x) for x in self.env.overall_pcs])))
        self.logger.debug("Instructions not executed: %s", sorted(diff))

        # delete the mutation files

        if os.path.isdir("./mutation"):
            for file in os.listdir("./mutation"):
                os.remove(os.path.join("./mutation", file))
        
        if os.path.isdir("./correction"):
            for file in os.listdir("./correction"):
                os.remove(os.path.join("./correction", file))