from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from angr import SimState


class AbstractState:
    """
    Defines an abstract state in a state graph. An abstract state is defined by a set of fields (AbstractStateFields)
    and the value of each field.
    """

    def __init__(self, fields: AbstractStateFields, values: dict[str, Any]):
        self.fields = fields
        self.values = values


class AbstractStateFields:
    def __init__(self, fields: dict[str, tuple[int, str, int]]):
        self.fields = fields

    def generate_abstract_state(self, state: SimState) -> tuple[tuple[str, Any]]:
        lst = []
        for field, (offset, type_, size) in self.fields.items():
            if type_ == "pin":
                try:
                    val = state.solver.eval(state.globals[offset])
                except KeyError:
                    val = 0
            elif type_ == "double":
                val = state.solver.eval(
                    state.memory.load(offset, size=size, endness=state.arch.memory_endness).raw_to_fp()
                )
            else:
                val = state.solver.eval(state.memory.load(offset, size=size, endness=state.arch.memory_endness))
            lst.append((field, val))
        return tuple(lst)
