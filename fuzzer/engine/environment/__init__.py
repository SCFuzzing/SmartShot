#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import *
import random

class FuzzingEnvironment:
    def __init__(self, **kwargs) -> None:
        self.nr_of_transactions = 0
        self.unique_individuals = set()
        self.code_coverage = set()
        self.children_code_coverage = dict()
        self.previous_code_coverage_length = 0

        self.visited_branches = dict()

        self.memoized_fitness = dict()
        self.memoized_storage = dict()
        self.memoized_symbolic_execution = dict()

        self.individual_branches = dict()

        self.data_dependencies = dict()

        # key: JUMPI path that this transaction traverses
        # value: a tuple which contains current analyzed tainted storage and its expression
        # as for the same JUMPIs traversed, consider the constraints identical
        self.tainted_storage = dict()

        # key: the constraints that involve timestamp/blocknumber/call
        # value: a dict which:
        # key: JUMPI path that this transaction traverses
        # value: a tuple, the constraints of this path(i.e. expression) 
        self.path_constraint = {"timestamp": {}, "blocknumber": {}, "call": {}}
        
        # key: storage | block.timestamp | block.number | call return
        # value: list of tuples : (current storage, input, block.timestamp, tainted_storage)
        self.constraint_snapshot = dict()
        
        # contains tuples, (jumpi_path, instruction["pc"])
        self.jumpi_path = set()

        self.s = Solver()
        set_option('auto_config', False)
        set_option('smt.phase_selection', 5)
        set_option('smt.arith.random_initial_value', True)
        set_option('smt.random_seed', random.randint(0, 2 ** 10))

        # vars that have been solved by the solver
        # key: vars
        # value: dicts, K results for each time solved, K could be a hyper parameter
        # the dict contains the solved value of the var and the corresponding inputs / block information
        self.solved_vars = dict()

        self.solved_vars_used = dict()
        self.last_used_var = dict()
        # solved_vars that are reserved for snapshots
        self.snapshot_reserved = dict()

        self.onchain_status = dict()

        self.taint_counter = 0

        self.__dict__.update(kwargs)
