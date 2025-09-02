from __future__ import annotations

import pprint
from collections.abc import Callable
from itertools import count
from typing import TYPE_CHECKING, Any

import claripy
import networkx
from angr.analyses.analysis import AnalysesHub, Analysis
from angr.sim_options import NO_CROSS_INSN_OPT, SYMBOL_FILL_UNCONSTRAINED_MEMORY, SYMBOL_FILL_UNCONSTRAINED_REGISTERS
from angr.state_plugins.inspect import BP, BP_AFTER, BP_BEFORE

if TYPE_CHECKING:
    from angr import SimState

    from .abstract_state import AbstractStateFields


class ConstraintLogger:
    """
    Logs constraints and where they are created via the on_adding_constraints callback.
    """

    def __init__(self, mapping: dict[claripy.ast.Base, tuple[int, int]]):
        self.mapping = mapping

    def on_adding_constraints(self, state: SimState):
        added_constraints = state._inspect_getattr("added_constraints", None)
        if not (
            len(added_constraints) == 1
            and (claripy.is_true(added_constraints[0]) or claripy.is_false(added_constraints[0]))
        ):
            for constraint in added_constraints:
                self.mapping[constraint] = state.scratch.irsb.addr, state.scratch.stmt_idx


class ExpressionLogger:
    """
    Logs symbolic expressions and where they are created via the on_register_write callback.
    """

    def __init__(self, mapping: dict[claripy.ast.Base, tuple[int, int]], variables: set[str]):
        self.mapping = mapping
        self.variables: set[str] = variables if variables else set()

    def on_memory_read(self, state: SimState):
        expr = state._inspect_getattr("mem_read_expr", None)
        if expr is not None and expr.symbolic and expr.variables.intersection(self.variables):
            mem_read_addr = state._inspect_getattr("mem_read_address", None)
            if mem_read_addr is not None:
                if isinstance(mem_read_addr, int):
                    self.mapping[expr] = mem_read_addr
                elif not mem_read_addr.symbolic:
                    self.mapping[expr] = mem_read_addr.concrete_value

    def on_register_write(self, state: SimState):
        expr = state._inspect_getattr("reg_write_expr", None)
        if expr is not None and expr.symbolic and expr.variables.intersection(self.variables):
            if expr not in self.mapping:
                # do not overwrite an existing source - it might have been from a memory read, which is the real source...
                self.mapping[expr] = state.scratch.irsb.addr, state.scratch.stmt_idx


class DefinitionNode:
    def __init__(self, variable: str, block_addr: int, stmt_idx: int):
        self.variable = variable
        self.block_addr = block_addr
        self.stmt_idx = stmt_idx

    def __eq__(self, other):
        return (
            isinstance(other, DefinitionNode)
            and self.variable == other.variable
            and self.block_addr == other.block_addr
        )

    def __hash__(self):
        return hash((DefinitionNode, self.variable, self.block_addr, self.stmt_idx))

    def __repr__(self):
        return f"{self.variable}@{self.block_addr:#x}:{self.stmt_idx}"


class SliceGenerator:
    def __init__(self, symbolic_exprs: set[claripy.ast.Base], bp: BP | None = None):
        self.bp: BP | None = bp
        self.symbolic_exprs = symbolic_exprs
        self.expr_variables = set()

        # FIXME: The algorithm is hackish and incorrect. We should fix it later.
        self._last_statements = {}
        self.slice = networkx.DiGraph()

        for expr in self.symbolic_exprs:
            self.expr_variables |= expr.variables

        if self.bp is not None:
            self.bp.action = self._examine_expr

    def install_expr_hook(self, state: SimState) -> BP:
        bp = BP(when=BP_AFTER, enabled=False, action=self._examine_expr)
        state.inspect.add_breakpoint("expr", bp)
        self.bp = bp
        return bp

    def _examine_expr(self, state: SimState):
        expr = state._inspect_getattr("expr_result", None)
        if state.solver.symbolic(expr) and expr.variables.intersection(self.expr_variables):

            variables = expr.variables
            curr_loc = state.scratch.irsb.addr, state.scratch.stmt_idx
            for v in variables:
                pred = self._last_statements.get(v, None)
                if pred is not None:
                    self.slice.add_edge(
                        DefinitionNode(v, pred[0], pred[1]), DefinitionNode(v, curr_loc[0], curr_loc[1])
                    )
                self._last_statements[v] = curr_loc
            # print(expr, state.scratch.irsb.statements[state.scratch.stmt_idx])


class StateGraphRecoveryAnalysis(Analysis):
    """
    Traverses a function and derive a state graph with respect to given variables.
    """

    def __init__(
        self,
        start_addr: int,
        fields: AbstractStateFields,
        software: str,
        time_addr: int | None,
        temp_addr: int = None,
        init_state: SimState | None = None,
        switch_on: Callable | None = None,
        printstate: Callable | None = None,
        config_vars: set[claripy.ast.Base] | None = None,
        patch_callback: Callable | None = None,
        input_data: dict | None = None,
        accurate_slice: bool = False,
        pre_exec_addr: int | None = None,
        low_priority: bool = False,
        job_state_callback: Callable | None = None,
    ):
        self.start_addr = start_addr
        self.fields = fields
        self.config_vars = config_vars if config_vars is not None else set()
        self.software = software
        self.init_state = init_state
        self._switch_on = switch_on
        self._ret_trap: int = 0x1F37FF4A
        self.printstate = printstate
        self.patch_callback = patch_callback
        self._low_priority = low_priority
        self._job_state_callback = job_state_callback
        self._accurate_slice = accurate_slice
        self._preexec_addr = pre_exec_addr

        self._time_addr = time_addr
        self._temp_addr = temp_addr

        self.throt_info = input_data.get("throt", None)
        self.throt = None

        self._tv_sec_var = None
        self._temperature = None
        self.state_graph = None
        self._expression_source = {}

        self.traverse()

    def traverse(self):

        # create an empty state graph
        self.state_graph = networkx.DiGraph()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)

        symbolic_input_fields = self._symbolize_var_fields(init_state)
        if self._time_addr is not None:
            symbolic_time_counters = self._symbolize_timecounter(init_state)
        else:
            symbolic_time_counters = {}

        if self._temp_addr is not None:
            symbolic_temperature = self._symbolize_temp(init_state)
        else:
            symbolic_temperature = {}

        if self.throt_info is not None:
            symbolic_throt = self._symbolize_throt(init_state)
        else:
            symbolic_throt = {}

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_input_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        if self._temp_addr is not None:
            all_vars |= set(symbolic_temperature.values())
        if self.throt_info is not None:
            all_vars | set(symbolic_throt.values())
        all_vars |= self.config_vars
        slice_gen = SliceGenerator(all_vars, bp=None)
        expression_bp = slice_gen.install_expr_hook(init_state)

        # setup inspection points to catch where expressions are written to registers
        expression_logger = ExpressionLogger(self._expression_source, {v.args[0] for v in all_vars})
        regwrite_bp = BP(when=BP_BEFORE, enabled=True, action=expression_logger.on_register_write)
        init_state.inspect.add_breakpoint("reg_write", regwrite_bp)
        memread_bp = BP(when=BP_AFTER, enabled=True, action=expression_logger.on_memory_read)
        init_state.inspect.add_breakpoint("mem_read", memread_bp)

        # Abstract state ID counter
        abs_state_id_ctr = count(0)

        abs_state = self.fields.generate_abstract_state(init_state)
        abs_state_id = next(abs_state_id_ctr)
        self.state_graph.add_node((("NODE_CTR", abs_state_id),) + abs_state, outvars=dict(abs_state))

        # FIXME:
        init_state = self._traverse_one(init_state, exec_addr=self._preexec_addr)

        state_queue = [(init_state, abs_state_id, abs_state, None, {})]
        if self._switch_on is None:
            countdown_timer = 0
            switched_on = True

            if self._time_addr is not None:
                time_delta_and_sources = self._discover_time_deltas(init_state)
                for delta, constraint, source in time_delta_and_sources:
                    if source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = source
                    print(f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}")

                temp_delta_and_sources = self._discover_temp_deltas(init_state)
                for delta, constraint, source in temp_delta_and_sources:
                    if source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = source
                    print(f"[.] Discovered a new temperature {delta} defined at {block_addr:#x}:{stmt_idx}")

                if temp_delta_and_sources or time_delta_and_sources:

                    if temp_delta_and_sources:

                        for temp_delta, temp_constraint, temp_src in temp_delta_and_sources:
                            # append two states in queue
                            op = temp_constraint.args[0].op
                            prev = init_state.memory.load(
                                self._temp_addr, 8, endness=self.project.arch.memory_endness
                            ).raw_to_fp()
                            prev_temp = init_state.solver.eval(prev)
                            if op in ["fpLEQ", "fpLT", "fpGEQ", "fpGT"]:
                                if prev_temp < temp_delta:
                                    delta0, temp_constraint0, temp_src0 = None, None, None
                                    delta1, temp_constraint1, temp_src1 = temp_delta + 1.0, temp_constraint, temp_src

                                    new_state = self._initialize_state(init_state=init_state)

                                    # re-symbolize input fields, time counters, and update slice generator
                                    symbolic_input_fields = self._symbolize_var_fields(new_state)
                                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                                    symbolic_temperature = self._symbolize_temp(new_state)
                                    all_vars = set(symbolic_input_fields.values())
                                    all_vars |= set(symbolic_time_counters.values())
                                    all_vars |= set(symbolic_temperature.values())
                                    all_vars |= self.config_vars
                                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                    state_queue.append(
                                        (
                                            new_state,
                                            abs_state_id,
                                            abs_state,
                                            None,
                                            {
                                                "time": (None, None, None),
                                                "temp": (delta1, temp_constraint1, temp_src1),
                                            },
                                        )
                                    )
                                elif prev_temp > temp_delta:
                                    delta0, temp_constraint0, temp_src0 = temp_delta - 1.0, temp_constraint, temp_src
                                    delta1, temp_constraint1, temp_src1 = None, None, None

                                    new_state = self._initialize_state(init_state=init_state)

                                    # re-symbolize input fields, time counters, and update slice generator
                                    symbolic_input_fields = self._symbolize_var_fields(new_state)
                                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                                    symbolic_temperature = self._symbolize_temp(new_state)
                                    all_vars = set(symbolic_input_fields.values())
                                    all_vars |= set(symbolic_time_counters.values())
                                    all_vars |= set(symbolic_temperature.values())
                                    all_vars |= self.config_vars
                                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                    state_queue.append(
                                        (
                                            new_state,
                                            abs_state_id,
                                            abs_state,
                                            None,
                                            {
                                                "time": (None, None, None),
                                                "temp": (delta0, temp_constraint0, temp_src0),
                                            },
                                        )
                                    )
                                else:
                                    import ipdb

                                    ipdb.set_trace()

                            elif op in ["fpEQ"]:
                                # import ipdb; ipdb.set_trace()
                                new_state = self._initialize_state(init_state=init_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_var_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append(
                                    (
                                        new_state,
                                        abs_state_id,
                                        abs_state,
                                        None,
                                        {"time": (None, None, None), "temp": (temp_delta, temp_constraint, temp_src)},
                                    )
                                )
                                continue

                            if time_delta_and_sources:
                                # print(time_delta_constraint)
                                for time_delta, time_constraint, time_src in time_delta_and_sources:
                                    # append state satisfy constraint
                                    new_state = self._initialize_state(init_state=init_state)

                                    # re-symbolize input fields, time counters, and update slice generator
                                    symbolic_input_fields = self._symbolize_var_fields(new_state)
                                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                                    symbolic_temperature = self._symbolize_temp(new_state)
                                    all_vars = set(symbolic_input_fields.values())
                                    all_vars |= set(symbolic_time_counters.values())
                                    all_vars |= set(symbolic_temperature.values())
                                    all_vars |= self.config_vars
                                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                    state_queue.append(
                                        (
                                            new_state,
                                            abs_state_id,
                                            abs_state,
                                            None,
                                            {
                                                "time": (time_delta, time_constraint, time_src),
                                                "temp": (delta0, temp_constraint0, temp_src0),
                                            },
                                        )
                                    )

                                    # append state not satisfy constraint
                                    new_state = self._initialize_state(init_state=init_state)

                                    # re-symbolize input fields, time counters, and update slice generator
                                    symbolic_input_fields = self._symbolize_var_fields(new_state)
                                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                                    symbolic_temperature = self._symbolize_temp(new_state)
                                    all_vars = set(symbolic_input_fields.values())
                                    all_vars |= set(symbolic_time_counters.values())
                                    all_vars |= set(symbolic_temperature.values())
                                    all_vars |= self.config_vars
                                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                    state_queue.append(
                                        (
                                            new_state,
                                            abs_state_id,
                                            abs_state,
                                            None,
                                            {
                                                "time": (time_delta, time_constraint, time_src),
                                                "temp": (delta1, temp_constraint1, temp_src1),
                                            },
                                        )
                                    )

                    # only discover time delta
                    else:
                        for time_delta, time_constraint, time_src in time_delta_and_sources:
                            new_state = self._initialize_state(init_state=init_state)

                            # re-symbolize input fields, time counters, and update slice generator
                            symbolic_input_fields = self._symbolize_var_fields(new_state)
                            symbolic_time_counters = self._symbolize_timecounter(new_state)
                            all_vars = set(symbolic_input_fields.values())
                            all_vars |= set(symbolic_time_counters.values())
                            if self._temp_addr is not None:
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars |= set(symbolic_temperature.values())
                            all_vars |= self.config_vars
                            slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                            state_queue.append(
                                (
                                    new_state,
                                    abs_state_id,
                                    abs_state,
                                    None,
                                    {
                                        "time": (time_delta, time_constraint, time_src),
                                        "temp": (None, None, None),
                                    },
                                )
                            )

            else:
                # if time_delta is None and prev_abs_state == abs_state:
                #     continue
                new_state = self._initialize_state(init_state=init_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_input_fields = self._symbolize_var_fields(new_state)
                symbolic_time_counters = self._symbolize_timecounter(new_state)

                all_vars = set(symbolic_input_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                if self._temp_addr is not None:
                    symbolic_temperature = self._symbolize_temp(new_state)
                    all_vars |= set(symbolic_temperature.values())
                all_vars |= self.config_vars
                slice_gen = SliceGenerator(all_vars, bp=expression_bp)

                state = (
                    new_state,
                    abs_state_id,
                    abs_state,
                    None,
                    {},
                )
                if self._time_addr is not None:
                    state[-1]["time"] = (None, None, None)
                if self._temp_addr is not None:
                    state[-1]["temp"] = (None, None, None)
                if self.throt_info is not None:
                    state[-1]["throt"] = (None, None, None)
                state_queue.append(state)
        else:
            countdown_timer = 2  # how many iterations to execute before switching on
            switched_on = False

        known_transitions = set()
        known_states = {}

        absstate_to_slice = {}
        while state_queue:
            if self._low_priority:
                self._release_gil(1, 1, sleep_time=0.000001)
            if self._job_state_callback is not None and self._job_state_callback() is False:
                print("[!] Job cancelled.")
                break

            (prev_state, prev_abs_state_id, prev_abs_state, prev_prev_abs, deltas) = state_queue.pop(0)

            if deltas.get("time", None) is not None:
                # advance the time stamp as required
                time_delta, time_delta_constraint, time_delta_src = deltas["time"]
                if time_delta is not None:
                    self._advance_timecounter(prev_state, time_delta)

            if deltas.get("temp", None) is not None:
                # advance the temperature stamp as required
                temp_delta, temp_delta_constraint, temp_delta_src = deltas["temp"]
                if temp_delta is not None:
                    self._advance_temp(prev_state, temp_delta)

            if deltas.get("throt", None) is not None:
                throt_delta, throt_delta_constraint, throt_delta_src = deltas["throt"]
                if throt_delta is not None:
                    self._advance_throt(prev_state, throt_delta)

            # symbolically trace the state
            expression_bp.enabled = True
            next_state = self._traverse_one(prev_state)

            if self._time_addr is not None:
                # print time
                print(
                    next_state.solver.eval(
                        next_state.memory.load(self._time_addr, 4, endness=self.project.arch.memory_endness)
                    )
                )

            expression_bp.enabled = False

            abs_state = self.fields.generate_abstract_state(next_state)

            if deltas.get("time", None) is not None:
                time_delta, time_delta_constraint, time_delta_src = deltas["time"]
                abs_state += (
                    ("time_delta", time_delta),
                    ("td_src", time_delta_src),
                )
            if deltas.get("temp", None) is not None:
                temp_delta, temp_delta_constraint, temp_delta_src = deltas["temp"]
                abs_state += (
                    ("temp_delta", temp_delta),
                    ("temp_src", temp_delta_src),
                )

            if switched_on:
                if abs_state in known_states:
                    abs_state_id = known_states[abs_state]
                else:
                    abs_state_id = next(abs_state_id_ctr)
                    known_states[abs_state] = abs_state_id
            else:
                abs_state_id = next(abs_state_id_ctr)

            print("[+] Discovered a new abstract state:")
            if self.printstate is None:
                pprint.pprint(abs_state)
            else:
                self.printstate(abs_state)
            absstate_to_slice[abs_state] = slice_gen.slice
            print("[.] There are %d nodes in the slice." % len(slice_gen.slice))

            transition = (prev_prev_abs, prev_abs_state, abs_state)
            if switched_on and transition in known_transitions:
                # update progress
                self.set_progress(state_queue)
                continue

            known_transitions.add(transition)
            edge_data = {}
            edge_label = []
            if deltas.get("time", None) is not None:
                time_delta, time_delta_constraint, time_delta_src = deltas["time"]
                edge_data.update(
                    {
                        "time_delta": time_delta,
                        "time_delta_constraint": time_delta_constraint,
                        "time_delta_src": time_delta_src,
                    }
                )
                edge_label += [f"time_delta={time_delta}"]
            if deltas.get("temp", None) is not None:
                temp_delta, temp_delta_constraint, temp_delta_src = deltas["temp"]
                edge_data.update(
                    {
                        "temp_delta": temp_delta,
                        "temp_delta_constraint": temp_delta_constraint,
                        "temp_delta_src": temp_delta_src,
                    }
                )
                edge_label += [f"temp_delta={temp_delta}"]
            if deltas.get("throt", None) is not None:
                throt_delta, throt_delta_constraint, throt_delta_src = deltas["throt"]
                edge_data.update(
                    {
                        "throt_delta": throt_delta,
                        "throt_delta_constraint": throt_delta_constraint,
                        "throt_delta_src": throt_delta_src,
                    }
                )
                edge_label += [f"throt_delta={throt_delta}"]

            if edge_label:
                edge_data["label"] = ",\n".join(edge_label)

            self.state_graph.add_node((("NODE_CTR", abs_state_id),) + abs_state, outvars=dict(abs_state))
            self.state_graph.add_edge(
                (("NODE_CTR", prev_abs_state_id),) + prev_abs_state,
                (("NODE_CTR", abs_state_id),) + abs_state,
                **edge_data,
            )

            if self._time_addr is not None:
                # discover time deltas
                if not switched_on and self._switch_on is not None:
                    if countdown_timer > 0:
                        print("[.] Pre-heat... %d" % countdown_timer)
                        countdown_timer -= 1
                        new_state = self._initialize_state(init_state=next_state)
                        state_queue.append(
                            (
                                new_state,
                                abs_state_id,
                                abs_state,
                                None,
                                {"time": (1, None, None), "temp": (None, None, None)},
                            )
                        )
                        continue
                    else:
                        print("[.] Switch on.")
                        self._switch_on(next_state)
                        if self.patch_callback is not None:
                            print("[.] Applying patches...")
                            self.patch_callback(next_state)
                        switched_on = True
                        time_delta_and_sources = {}
                        temp_delta_and_sources = {}
                        prev_abs_state = None
                        # state_queue.append((new_state, abs_state_id, abs_state, None, None, None, None, None, None))
                else:
                    time_delta_and_sources = self._discover_time_deltas(next_state)

                    for delta, constraint, source in time_delta_and_sources:
                        if source is None:
                            block_addr, stmt_idx = -1, -1
                        else:
                            block_addr, stmt_idx = source
                        print(f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}")
                    if self._temp_addr is not None:
                        temp_delta_and_sources = self._discover_temp_deltas(next_state)
                        for delta, constraint, source in temp_delta_and_sources:
                            if source is None:
                                block_addr, stmt_idx = -1, -1
                            else:
                                block_addr, stmt_idx = source
                            print(f"[.] Discovered a new temperature {delta} defined at {block_addr:#x}:{stmt_idx}")

                if temp_delta_and_sources or time_delta_and_sources:

                    if temp_delta_and_sources:

                        for temp_delta, temp_constraint, temp_src in temp_delta_and_sources:
                            # append two states in queue
                            op = temp_constraint.args[0].op
                            prev = next_state.memory.load(
                                self._temp_addr, 8, endness=self.project.arch.memory_endness
                            ).raw_to_fp()
                            prev_temp = next_state.solver.eval(prev)
                            if op in ["fpLEQ", "fpLT", "fpGEQ", "fpGT"]:
                                if prev_temp < temp_delta:
                                    delta0, temp_constraint0, temp_src0 = None, None, None
                                    delta1, temp_constraint1, temp_src1 = temp_delta + 1.0, temp_constraint, temp_src

                                    new_state = self._initialize_state(init_state=next_state)

                                    # re-symbolize input fields, time counters, and update slice generator
                                    symbolic_input_fields = self._symbolize_var_fields(new_state)
                                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                                    symbolic_temperature = self._symbolize_temp(new_state)
                                    all_vars = set(symbolic_input_fields.values())
                                    all_vars |= set(symbolic_time_counters.values())
                                    all_vars |= set(symbolic_temperature.values())
                                    all_vars |= self.config_vars
                                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                    state_queue.append(
                                        (
                                            new_state,
                                            abs_state_id,
                                            abs_state,
                                            prev_abs_state,
                                            {
                                                "time": (None, None, None),
                                                "temp": (delta1, temp_constraint1, temp_src1),
                                            },
                                        )
                                    )
                                elif prev_temp > temp_delta:
                                    delta0, temp_constraint0, temp_src0 = temp_delta - 1.0, temp_constraint, temp_src
                                    delta1, temp_constraint1, temp_src1 = None, None, None

                                    new_state = self._initialize_state(init_state=next_state)

                                    # re-symbolize input fields, time counters, and update slice generator
                                    symbolic_input_fields = self._symbolize_var_fields(new_state)
                                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                                    symbolic_temperature = self._symbolize_temp(new_state)
                                    all_vars = set(symbolic_input_fields.values())
                                    all_vars |= set(symbolic_time_counters.values())
                                    all_vars |= set(symbolic_temperature.values())
                                    all_vars |= self.config_vars
                                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                    state_queue.append(
                                        (
                                            new_state,
                                            abs_state_id,
                                            abs_state,
                                            prev_abs_state,
                                            {
                                                "time": (None, None, None),
                                                "temp": (delta0, temp_constraint0, temp_src0),
                                            },
                                        )
                                    )
                                else:
                                    import ipdb

                                    ipdb.set_trace()

                            elif op in ["fpEQ"]:
                                # import ipdb; ipdb.set_trace()
                                new_state = self._initialize_state(init_state=next_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_var_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append(
                                    (
                                        new_state,
                                        abs_state_id,
                                        abs_state,
                                        prev_abs_state,
                                        {
                                            "time": (None, None, None),
                                            "temp": (temp_delta, temp_constraint, temp_src),
                                        },
                                    )
                                )
                                continue

                            if time_delta_and_sources:
                                # print(time_delta_constraint)
                                for time_delta, time_constraint, time_src in time_delta_and_sources:
                                    # append state satisfy constraint
                                    new_state = self._initialize_state(init_state=next_state)

                                    # re-symbolize input fields, time counters, and update slice generator
                                    symbolic_input_fields = self._symbolize_var_fields(new_state)
                                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                                    symbolic_temperature = self._symbolize_temp(new_state)
                                    all_vars = set(symbolic_input_fields.values())
                                    all_vars |= set(symbolic_time_counters.values())
                                    all_vars |= set(symbolic_temperature.values())
                                    all_vars |= self.config_vars
                                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                    state_queue.append(
                                        (
                                            new_state,
                                            abs_state_id,
                                            abs_state,
                                            prev_abs_state,
                                            {
                                                "time": (time_delta, time_constraint, time_src),
                                                "temp": (delta0, temp_constraint0, temp_src0),
                                            },
                                        )
                                    )

                                    # append state not satisfy constraint
                                    new_state = self._initialize_state(init_state=next_state)

                                    # re-symbolize input fields, time counters, and update slice generator
                                    symbolic_input_fields = self._symbolize_var_fields(new_state)
                                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                                    symbolic_temperature = self._symbolize_temp(new_state)
                                    all_vars = set(symbolic_input_fields.values())
                                    all_vars |= set(symbolic_time_counters.values())
                                    all_vars |= set(symbolic_temperature.values())
                                    all_vars |= self.config_vars
                                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                    state_queue.append(
                                        (
                                            new_state,
                                            abs_state_id,
                                            abs_state,
                                            prev_abs_state,
                                            {
                                                "time": (time_delta, time_constraint, time_src),
                                                "temp": (delta1, temp_constraint1, temp_src1),
                                            },
                                        )
                                    )

                    # only discover time delta
                    else:
                        for time_delta, time_constraint, time_src in time_delta_and_sources:
                            new_state = self._initialize_state(init_state=next_state)

                            # re-symbolize input fields, time counters, and update slice generator
                            symbolic_input_fields = self._symbolize_var_fields(new_state)
                            symbolic_time_counters = self._symbolize_timecounter(new_state)
                            all_vars = set(symbolic_input_fields.values())
                            all_vars |= set(symbolic_time_counters.values())
                            if self._temp_addr is not None:
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars |= set(symbolic_temperature.values())
                            all_vars |= self.config_vars
                            slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                            state_queue.append(
                                (
                                    new_state,
                                    abs_state_id,
                                    abs_state,
                                    prev_abs_state,
                                    {"time": (time_delta, time_constraint, time_src), "temp": (None, None, None)},
                                )
                            )

                else:
                    new_state = self._initialize_state(init_state=next_state)

                    # re-symbolize input fields, time counters, and update slice generator
                    symbolic_input_fields = self._symbolize_var_fields(new_state)
                    symbolic_time_counters = self._symbolize_timecounter(new_state)

                    all_vars = set(symbolic_input_fields.values())
                    all_vars |= set(symbolic_time_counters.values())
                    if self._temp_addr is not None:
                        symbolic_temperature = self._symbolize_temp(new_state)
                        all_vars |= set(symbolic_temperature.values())
                    all_vars |= self.config_vars
                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)

                    state_queue.append(
                        (
                            new_state,
                            abs_state_id,
                            abs_state,
                            prev_abs_state,
                            {"time": (None, None, None), "temp": (None, None, None)},
                        )
                    )

            else:
                # throt-specific
                for throt_delta, throt_constraint, throt_src in self._discover_throt_deltas(next_state):
                    if self._low_priority:
                        self._release_gil(1, 1, sleep_time=0.000001)
                    if self._job_state_callback is not None and self._job_state_callback() is False:
                        print("[!] Job cancelled.")
                        break

                    if throt_src is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = throt_src
                    print(f"[.] Discovered a new throttle delta {throt_delta} defined at {block_addr:#x}:{stmt_idx}")

                    new_state = self._initialize_state(init_state=next_state)

                    # re-symbolize input fields, time counters, and update slice generator
                    symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                    # symbolic_time_counters = self._symbolize_timecounter(new_state)
                    symbolic_throt = self._symbolize_throt(new_state)
                    all_vars = set(symbolic_abstate_fields.values())
                    # all_vars |= set(symbolic_time_counters.values())
                    all_vars |= set(symbolic_throt.values())
                    all_vars |= self.config_vars
                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                    state_queue.append(
                        (
                            new_state,
                            abs_state_id,
                            abs_state,
                            prev_abs_state,
                            {
                                "throt": (throt_delta, throt_constraint, throt_src),
                            },
                        )
                    )

            print(f"[.] State graph has {len(self.state_graph)} states and {len(self.state_graph.edges)} transitions.")
            print(f"[.] State queue has {len(state_queue)} entries.")

            if self._job_state_callback is None or (
                self._job_state_callback is not None and self._job_state_callback() is True
            ):
                # update progress
                self.set_progress(state_queue)

        if self._job_state_callback is None or (
            self._job_state_callback is not None and self._job_state_callback() is True
        ):
            self._finish_progress()

    def set_progress(self, state_queue: list) -> None:
        ram_usage = self.ram_usage / (1024 * 1024)
        txt = (
            f"{len(self.state_graph)} states, {len(self.state_graph.edges)} transitions | "
            f"{len(state_queue)} remaining jobs | "
            f"{ram_usage:0.2f} MB RAM"
        )
        self._update_progress(50.0, text=txt)

    def _discover_time_deltas(self, state: SimState) -> list[tuple[int, claripy.ast.Base, tuple[int, int]]]:
        """
        Discover all possible time intervals that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """

        state = self._initialize_state(state)
        time_deltas = self._symbolically_advance_timecounter(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint("constraints", bp_0)

        next_state = self._traverse_one(state)
        # import ipdb; ipdb.set_trace()
        # detect required time delta
        # TODO: Extend it to more than just seconds
        steps: list[tuple[int, claripy.ast.Base, tuple[int, int]]] = []
        if time_deltas:
            for delta in time_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint
                    # attempt simplification if this constraint has both config variables and time delta variables
                    if (
                        any(x.args[0] in constraint.variables for x in self.config_vars)
                        and delta.args[0] in constraint.variables
                    ):
                        simplified_constraint, self._expression_source = self._simplify_constraint(
                            constraint, self._expression_source
                        )
                        if simplified_constraint is not None:
                            constraint = simplified_constraint

                    if delta.args[0] not in constraint.variables:
                        continue

                    if constraint.op == "__eq__" and constraint.args[0] is delta:
                        continue
                    elif constraint.op in ("ULE"):  # arduino arm32
                        if constraint.args[0].args[1] is delta:
                            if constraint.args[1].args[0].op == "BVV":
                                step = constraint.args[1].args[0].args[0]
                                if step != 0:
                                    steps.append(
                                        (
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint),
                                        )
                                    )
                                    continue
                    elif constraint.op in ("__le__",):  # simulink arm32
                        if constraint.args[0].args[1] is delta:
                            if constraint.args[1].op == "BVV":
                                step = constraint.args[1].args[0]
                                if step != 0 and step < 255:
                                    steps.append(
                                        (
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint),
                                        )
                                    )
                                    continue
                            elif constraint.args[1].args[0].op == "BVV":  # arduino arm32 oven
                                step = constraint.args[1].args[0].args[0]
                                if step != 0:
                                    steps.append(
                                        (
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint),
                                        )
                                    )
                                    continue
                    elif constraint.op == "__ne__":
                        if constraint.args[0] is delta:  # amd64
                            # found a potential step
                            if constraint.args[1].op == "BVV":
                                step = constraint.args[1].concrete_value
                                if step != 0 and step < 255:
                                    steps.append(
                                        (
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint),
                                        )
                                    )
                                    continue
                            else:
                                # attempt to evaluate the right-hand side
                                values = state.solver.eval_upto(constraint.args[1], 2)
                                if len(values) == 1:
                                    # it has a single value!
                                    step = values[0]
                                    if step != 0:
                                        steps.append(
                                            (
                                                step,
                                                constraint,
                                                constraint_source.get(original_constraint),
                                            )
                                        )
                                        continue

                        if constraint.args[1].op == "BVS":  # arm32
                            # access constraint.args[1].args[2]
                            if constraint.args[1].args[2] is delta or constraint.args[1] is delta:
                                if constraint.args[0].op == "BVV":
                                    step = constraint.args[0].args[0]
                                    if step != 0:
                                        steps.append(
                                            (
                                                step,
                                                constraint,
                                                constraint_source.get(original_constraint),
                                            )
                                        )
                                        continue
        return steps

    def _discover_temp_deltas(self, state: SimState) -> list[tuple[int, claripy.ast.Base, tuple[int, int]]]:
        """
        Discover all possible temperature that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self._temp_addr is None:
            return []
        state = self._initialize_state(state)
        temp_deltas = self._symbolically_advance_temp(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint("constraints", bp_0)

        next_state = self._traverse_one(state)

        # detect required temp delta
        steps: list[tuple[int, claripy.ast.Base, tuple[int, int]]] = []
        if temp_deltas:
            for delta in temp_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if constraint.op == "__eq__" and constraint.args[0] is delta:
                        continue
                    elif constraint.op == "Not":
                        if len(constraint.args[0].args[1].args) > 2:
                            if constraint.args[0].args[1].args[2] is delta:
                                if constraint.args[0].args[0].op == "FPV":
                                    step = constraint.args[0].args[0].concrete_value
                                    if step != 0 and step < 10000:
                                        # if step != 0:
                                        steps.append(
                                            (
                                                step,
                                                constraint,
                                                constraint_source.get(original_constraint),
                                            )
                                        )
                                        continue
                        elif len(constraint.args[0].args[0].args) > 2:
                            if constraint.args[0].args[0].args[2] is delta:
                                if constraint.args[0].args[1].op == "FPV":
                                    step = constraint.args[0].args[1].concrete_value
                                    if step != 0 and step < 10000:
                                        steps.append(
                                            (
                                                step,
                                                constraint,
                                                constraint_source.get(original_constraint),
                                            )
                                        )
                                        continue

        return steps

    def _discover_throt_deltas(self, state: SimState) -> list[tuple[int, claripy.ast.Base, tuple[int, int]]]:
        """
        Discover all possible water level that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required throt.
        """
        if self.throt is None:
            return []
        state = self._initialize_state(state)
        # import ipdb; ipdb.set_trace()
        throt_deltas = self._symbolically_advance_throt(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint("constraints", bp_0)

        next_states = self._traverse_one(state, discover=True)
        # import ipdb; ipdb.set_trace()
        # detect required throt delta
        steps: list[tuple[int, claripy.ast.Base, tuple[int, int]]] = []
        for next_state in next_states:
            for delta in throt_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if delta.args[0] in constraint.variables:
                        # import ipdb; ipdb.set_trace()
                        step = next_state.solver.min(delta)

                        steps.append(
                            (
                                step,
                                constraint,
                                constraint_source.get(original_constraint),
                            )
                        )
                        break

                    else:
                        continue
        pprint.pprint(steps)
        return steps

    def _simplify_constraint(
        self, constraint: claripy.ast.Base, source: dict[claripy.ast.Base, Any]
    ) -> tuple[claripy.ast.Base | None, dict[claripy.ast.Base, Any]]:
        """
        Attempt to simplify a constraint and generate a new source mapping.

        Note that this simplification focuses on readability and is not always sound!

        :param constraint:
        :param source:
        :return:
        """

        if (
            constraint.op in ("__ne__", "__eq__", "ULE")
            and constraint.args[0].op == "__add__"
            and constraint.args[1].op == "__add__"
        ):
            # remove arguments that appear in both sides of the comparison
            same_args = set(constraint.args[0].args).intersection(set(constraint.args[1].args))
            if same_args:
                left_new_args = tuple(arg for arg in constraint.args[0].args if arg not in same_args)
                left = (
                    constraint.args[0].make_like("__add__", left_new_args)
                    if len(left_new_args) > 1
                    else left_new_args[0]
                )
                if constraint.args[0] in source:
                    source[left] = source[constraint.args[0]]

                right_new_args = tuple(arg for arg in constraint.args[1].args if arg not in same_args)
                right = (
                    constraint.args[1].make_like("__add__", right_new_args)
                    if len(right_new_args) > 1
                    else right_new_args[0]
                )
                if constraint.args[1] in source:
                    source[right] = source[constraint.args[1]]

                simplified = constraint.make_like(constraint.op, (left, right))
                if constraint in source:
                    source[simplified] = source[constraint]
                return self._simplify_constraint(simplified, source)

        # Transform signed-extension of fpToSBV() to unsigned extension
        if constraint.op == "Concat":
            args = constraint.args
            if all(arg.op == "Extract" for arg in args):
                if len(set(arg.args[2] for arg in args)) == 1:
                    if all(arg.args[0:2] in ((15, 15), (31, 31)) for arg in args[:-1]):
                        # found it!
                        core, source = self._simplify_constraint(args[0].args[2], source)
                        if core is None:
                            core = args[0].args[2]
                        simplified = claripy.ZeroExt(len(args) - 1, core)
                        if constraint in source:
                            source[simplified] = source[constraint]
                        return simplified, source
            elif all(arg.op == "Extract" for arg in args[:-1]):
                if len(set(arg.args[2] for arg in args[:-1])) == 1:
                    v = args[0].args[2]
                    if v is args[-1]:
                        if all(arg.args[0:2] in ((15, 15), (31, 31)) for arg in args[:-1]):
                            # found it!
                            core, source = self._simplify_constraint(v, source)
                            if core is None:
                                core = v
                            simplified = claripy.ZeroExt(len(args) - 1, core)
                            if constraint is source:
                                source[simplified] = source[constraint]
                            return simplified, source

        elif constraint.op in ("__ne__", "__mod__", "__floordiv__"):
            left, source = self._simplify_constraint(constraint.args[0], source)
            right, source = self._simplify_constraint(constraint.args[1], source)
            if left is None and right is None:
                return None, source
            if left is None:
                left = constraint.args[0]
            if right is None:
                right = constraint.args[1]
            simplified = constraint.make_like(constraint.op, (left, right))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        elif constraint.op in ("__add__",):
            new_args = []
            simplified = False
            for arg in constraint.args:
                new_arg, source = self._simplify_constraint(arg, source)
                if new_arg is not None:
                    new_args.append(new_arg)
                    simplified = True
                else:
                    new_args.append(arg)
            if not simplified:
                return None, source
            simplified = constraint.make_like(constraint.op, tuple(new_args))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        elif constraint.op in ("fpToSBV", "fpToFP"):
            arg1, source = self._simplify_constraint(constraint.args[1], source)
            if arg1 is None:
                return None, source
            simplified = constraint.make_like(constraint.op, (constraint.args[0], arg1, constraint.args[2]))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        elif constraint.op in ("fpMul",):
            if constraint.args[1].op == "FPV" and constraint.args[1].concrete_value == 0.0:
                return constraint.args[1], source
            elif constraint.args[2].op == "FPV" and constraint.args[2].concrete_value == 0.0:
                return constraint.args[2], source
            arg1, source = self._simplify_constraint(constraint.args[1], source)
            arg2, source = self._simplify_constraint(constraint.args[2], source)
            if arg1 is None and arg2 is None:
                return None, source
            if arg1 is None:
                arg1 = constraint.args[1]
            if arg2 is None:
                arg2 = constraint.args[2]
            simplified = constraint.make_like(constraint.op, (constraint.args[0], arg1, arg2))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        return None, source

    def _symbolize_var_fields(
        self, state: SimState, fields: AbstractStateFields | None = None
    ) -> dict[str, claripy.ast.Base]:

        symbolic_input_vars = {}

        if fields is None:
            fields = self.fields

        for name, (address, type_, size) in fields.fields.items():
            # print(f"[.] Symbolizing field {name}...")

            v = state.memory.load(address, size=size, endness=self.project.arch.memory_endness)
            if not state.solver.symbolic(v):
                # if type_ == "float":
                #     concrete_v = state.solver.eval(v, cast_to=float)
                #     symbolic_v = claripy.FPS(name, claripy.fp.FSORT_FLOAT)
                # elif type_ == "double":
                #     concrete_v = state.solver.eval(v, cast_to=float)
                #     symbolic_v = claripy.FPS(name, claripy.fp.FSORT_DOUBLE)
                # else:
                concrete_v = state.solver.eval(v)
                symbolic_v = claripy.BVS(name, size * self.project.arch.byte_width)
                symbolic_input_vars[name] = symbolic_v

                # update the value in memory
                state.memory.store(address, symbolic_v, endness=self.project.arch.memory_endness)

                # preconstrain it
                state.preconstrainer.preconstrain(concrete_v, symbolic_v)
            else:
                symbolic_input_vars[name] = v

        return symbolic_input_vars

    def _symbolize_timecounter(self, state: SimState) -> dict[str, claripy.ast.Base]:
        if self.software == "beremiz":
            return self._symbolize_timecounter_beremiz(state)
        elif self.software == "arduino":
            return self._symbolize_timecounter_arduino(state)
        elif self.software == "simulink":
            return self._symbolize_timecounter_simulink(state)
        return {}

    # simulink time 255
    def _symbolize_timecounter_simulink(self, state: SimState) -> dict[str, claripy.ast.Base]:
        tv_sec_addr = self._time_addr

        self._tv_sec_var = claripy.BVS("tv_sec", 1 * self.project.arch.byte_width)
        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(0, 1 * self.project.arch.byte_width), self._tv_sec_var)

        return {"tv_sec": self._tv_sec_var}

    # Traffic_Light Beremiz
    def _symbolize_timecounter_beremiz(self, state: SimState) -> dict[str, claripy.ast.Base]:
        tv_sec_addr = self._time_addr
        tv_nsec_addr = tv_sec_addr + self.project.arch.bytes

        self._tv_sec_var = claripy.BVS("tv_sec", self.project.arch.bytes * self.project.arch.byte_width)
        self._tv_nsec_var = claripy.BVS("tv_nsec", self.project.arch.bytes * self.project.arch.byte_width)

        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.memory.store(tv_nsec_addr, self._tv_nsec_var, endness=self.project.arch.memory_endness)

        # the initial timer values are 0
        state.preconstrainer.preconstrain(
            claripy.BVV(0, self.project.arch.bytes * self.project.arch.byte_width), self._tv_sec_var
        )
        state.preconstrainer.preconstrain(
            claripy.BVV(0, self.project.arch.bytes * self.project.arch.byte_width), self._tv_nsec_var
        )

        return {"tv_sec_var": self._tv_sec_var, "tv_nsec_var": self._tv_nsec_var}

    # reflowoven Arduino
    def _symbolize_timecounter_arduino(self, state: SimState) -> dict[str, claripy.ast.Base]:
        tv_sec_addr = self._time_addr
        prev = state.memory.load(
            self._time_addr, size=self.project.arch.bytes, endness=self.project.arch.memory_endness
        )
        prev_time = state.solver.eval(prev) + 1

        self._tv_sec_var = claripy.BVS("tv_sec", self.project.arch.bytes * self.project.arch.byte_width)
        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(
            claripy.BVV(prev_time, self.project.arch.bytes * self.project.arch.byte_width), self._tv_sec_var
        )

        return {"tv_sec": self._tv_sec_var}

    def _symbolically_advance_timecounter(self, state: SimState) -> list[claripy.ast.Bits]:
        bytesize = self.project.arch.bytes
        if self.software == "simulink":
            bytesize = 1
        sec_delta = claripy.BVS("sec_delta", bytesize * self.project.arch.byte_width)
        state.preconstrainer.preconstrain(claripy.BVV(1, bytesize * self.project.arch.byte_width), sec_delta)

        tv_sec = state.memory.load(self._time_addr, size=bytesize, endness=self.project.arch.memory_endness)
        state.memory.store(self._time_addr, tv_sec + sec_delta, endness=self.project.arch.memory_endness)

        return [sec_delta]

    def _advance_timecounter(self, state: SimState, delta: int) -> None:
        bytesize = self.project.arch.bytes
        if self.software == "simulink":
            bytesize = 1
        prev = state.memory.load(self._time_addr, size=bytesize, endness=self.project.arch.memory_endness)
        state.memory.store(self._time_addr, prev + delta, endness=self.project.arch.memory_endness)

        if self.software == "beremiz":
            tv_nsec = state.memory.load(
                self._time_addr + self.project.arch.bytes,
                size=self.project.arch.bytes,
                endness=self.project.arch.memory_endness,
            )
            state.memory.store(
                self._time_addr + self.project.arch.bytes, tv_nsec + 200, endness=self.project.arch.memory_endness
            )

    def _symbolize_temp(self, state: SimState) -> dict[str, claripy.ast.Base]:
        temp_addr = self._temp_addr

        prev = state.memory.load(self._temp_addr, size=8, endness=self.project.arch.memory_endness)
        prev_temp = state.solver.eval(prev)

        self._temperature = claripy.FPS("temperature", claripy.fp.FSORT_DOUBLE)
        state.memory.store(temp_addr, self._temperature, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(state.solver.BVV(prev_temp, 64).raw_to_fp(), self._temperature)

        return {"temperature": self._temperature}

    def _symbolically_advance_temp(self, state: SimState) -> list[claripy.ast.Bits]:
        temp_delta = claripy.FPS("temp_delta", claripy.fp.FSORT_DOUBLE)
        state.preconstrainer.preconstrain(state.solver.FPV(0.5, claripy.fp.FSORT_DOUBLE), temp_delta)

        prev = state.memory.load(self._temp_addr, size=8, endness=self.project.arch.memory_endness).raw_to_fp()
        state.memory.store(self._temp_addr, prev + temp_delta, endness=self.project.arch.memory_endness)

        return [temp_delta]

    def _advance_temp(self, state: SimState, delta) -> None:
        self._temperature = claripy.FPS("temperature", claripy.fp.FSORT_DOUBLE)
        state.memory.store(self._temp_addr, self._temperature, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.FPV(delta, claripy.fp.FSORT_DOUBLE), self._temperature)

    def _symbolize_throt(self, state: SimState) -> dict[str, claripy.ast.Base]:
        (throt_addr, throt_sort, throt_size) = self.throt_info
        prev = state.memory.load(throt_addr, size=throt_size, endness=self.project.arch.memory_endness)
        prev_throt = state.solver.eval(prev)
        self.throt = claripy.BVS("throt", throt_size * self.project.arch.byte_width)
        state.memory.store(throt_addr, self.throt, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(
            claripy.BVV(prev_throt, throt_size * self.project.arch.byte_width), self.throt
        )
        return {"throt": self.throt}

    def _symbolically_advance_throt(self, state: SimState) -> list[claripy.ast.Bits]:
        (throt_addr, throt_sort, throt_size) = self.throt_info
        throt_delta = claripy.BVS("throt_delta", throt_size * self.project.arch.byte_width)
        state.memory.store(throt_addr, throt_delta, endness=self.project.arch.memory_endness)
        return [throt_delta]

    def _advance_throt(self, state: SimState, delta) -> None:
        (throt_addr, throt_sort, throt_size) = self.throt_info
        self.throt = claripy.BVS("throt", throt_size * self.project.arch.byte_width)
        state.memory.store(throt_addr, self.throt, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(delta, throt_size * self.project.arch.byte_width), self.throt)

    def _traverse_one(self, state: SimState, discover: bool = False, exec_addr: int | None = None):

        if exec_addr is not None:
            state._ip = exec_addr
        simgr = self.project.factory.simgr(state)

        while simgr.active:
            simgr.step()
            s = simgr.active[0]
            # print(s)
            if discover is False and len(simgr.active) > 1:
                # FIXME: Generate a warning
                # only leave the first active state
                simgr.active = [simgr.active[0]]

            simgr.stash(lambda x: x.addr == self._ret_trap, from_stash="active", to_stash="finished")
            # we assume we never get back to the start address
            simgr.stash(lambda x: x.addr == self.start_addr, from_stash="active", to_stash="finished")

        if discover:
            return simgr.finished
        else:
            assert len(simgr.finished) == 1
            return simgr.finished[0]

    def _initialize_state(self, init_state=None) -> SimState:
        if init_state is not None:
            s = init_state.copy()
            s.ip = self.start_addr
        else:
            s = self.project.factory.blank_state(addr=self.start_addr)
            s.regs.rdi = 0xC0000000
            s.memory.store(0xC0000000, b"\x00" * 0x1000)

        # disable cross instruction optimization so that statement IDs in symbolic execution will match the ones used in
        # static analysis
        s.options[NO_CROSS_INSN_OPT] = self._accurate_slice
        # disable warnings
        s.options[SYMBOL_FILL_UNCONSTRAINED_MEMORY] = True
        s.options[SYMBOL_FILL_UNCONSTRAINED_REGISTERS] = True

        if self.project.arch.call_pushes_ret:
            s.stack_push(claripy.BVV(self._ret_trap, self.project.arch.bits))
        else:
            # set up the link register for the return address
            s.regs.lr = self._ret_trap

        return s


AnalysesHub.register_default("StateGraphRecovery", StateGraphRecoveryAnalysis)
