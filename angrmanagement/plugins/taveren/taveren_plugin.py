from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimMemoryVariable

from angrmanagement.plugins import BasePlugin

from .fsm_recovery_dialog import RecoverFSMDialog

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from angrmanagement.ui.workspace import Workspace


class TaverenPlugin(BasePlugin):
    """Taveren plugin for angr management."""

    MENU_BUTTONS = [
        "Taveren: Recover an FSM...",
    ]

    def __init__(self, workspace: Workspace):
        super().__init__(workspace)

        self.config = {}

    # Internal methods

    def on_recover_fsm_clicked(self):
        # display the FSM recovery dialog
        dlg = RecoverFSMDialog(self.workspace, config=self.config)
        dlg.exec_()

    def _on_set_scan_cycle_start_triggered(self, addr: int):
        self.config["scan_cycle_function"] = addr

    def _on_set_scan_cycle_preexec_addr_triggered(self, addr: int):
        self.config["scan_cycle_pre_exec_addr"] = addr

    def _on_set_initializer_function_triggered(self, addr: int):
        self.config["initializer_function"] = addr

    def _on_set_initializer_function_early_exit_triggered(self, addr: int):
        self.config["initializer_function_early_exit"] = addr

    def _on_add_mmio_entry_triggered(self, addr: int, size: int | None = None):
        dlg = RecoverFSMDialog(self.workspace, config=self.config)
        dlg.add_mmio_setup(addr, size=size)
        dlg.exec_()

    def _on_remove_mmio_entry_triggered(self, addr: int):
        if "initializer_mmio_setup" not in self.config:
            return
        mmios = self.config["initializer_mmio_setup"]
        for i, mmio in list(enumerate(mmios)):
            if mmio["address"] == addr:
                mmios.pop(i)
                break

    def _on_add_variable_triggered(self, addr: int, size: int | None = None):
        dlg = RecoverFSMDialog(self.workspace, config=self.config)
        dlg.add_variable(addr, size=size)
        dlg.exec_()

    def _on_remove_variable_triggered(self, addr: int):
        if "variables" not in self.config:
            return
        variables = self.config["variables"]
        for i, var in list(enumerate(variables)):
            if var["address"] == addr:
                variables.pop(i)
                break

    def _has_mmio_entry(self, addr: int) -> bool:
        if "initializer_mmio_setup" not in self.config:
            return False
        mmios = self.config["initializer_mmio_setup"]
        return any(mmio["address"] == addr for mmio in mmios)

    def _has_variable(self, addr: int) -> bool:
        if "variables" not in self.config:
            return False
        variables = self.config["variables"]
        return any(var["address"] == addr for var in variables)

    # Menus

    def build_context_menu_insn(self, insn) -> Iterable[None | tuple[str, Callable]]:
        yield None  # separator
        yield "Taveren: Set as scan cycle start", partial(self._on_set_scan_cycle_start_triggered, insn.addr)
        yield "Taveren: Set as scan cycle pre-execution point", partial(
            self._on_set_scan_cycle_preexec_addr_triggered, insn.addr
        )
        yield "Taveren: Set as initialization function", partial(self._on_set_initializer_function_triggered, insn.addr)
        yield "Taveren: End the execution of initialization function at this point", partial(
            self._on_set_initializer_function_early_exit_triggered, insn.addr
        )

    def build_context_menu_label(self, addr: int):
        yield None  # separator
        yield "Taveren: Set as scan cycle start", partial(self._on_set_scan_cycle_start_triggered, addr)
        yield "Taveren: Set as scan cycle pre-execution point", partial(
            self._on_set_scan_cycle_preexec_addr_triggered, addr
        )
        yield "Taveren: Set as initialization function", partial(self._on_set_initializer_function_triggered, addr)
        yield "Taveren: End the execution of initialization function at this point", partial(
            self._on_set_initializer_function_early_exit_triggered, addr
        )
        if not self._has_mmio_entry(addr):
            yield "Taveren: Add as an MMIO entry...", partial(self._on_add_mmio_entry_triggered, addr)
        else:
            yield "Taveren: Remove MMIO entry", partial(self._on_remove_mmio_entry_triggered, addr)
        if not self._has_variable(addr):
            yield "Taveren: Add as a key variable...", partial(self._on_add_variable_triggered, addr)
        else:
            yield "Taveren: Remove key variable", partial(self._on_remove_variable_triggered, addr)

    def build_context_menu_node(self, node) -> Iterable[None | tuple[str, Callable]]:
        if (
            isinstance(node, CVariable)
            and isinstance(node.variable, SimMemoryVariable)
            and isinstance(node.variable.addr, int)
        ):
            yield None
            if not self._has_mmio_entry(node.variable.addr):
                yield "Taveren: Add as an MMIO entry...", partial(
                    self._on_add_mmio_entry_triggered, node.variable.addr, size=node.variable.size
                )
            else:
                yield "Taveren: Remove MMIO entry", partial(self._on_remove_mmio_entry_triggered, node.variable.addr)
            if not self._has_variable(node.variable.addr):
                yield "Taveren: Add as a key variable...", partial(
                    self._on_add_variable_triggered, node.variable.addr, size=node.variable.size
                )
            else:
                yield "Taveren: Remove key variable", partial(self._on_remove_variable_triggered, node.variable.addr)

    # Event handlers

    def handle_click_menu(self, idx: int):
        # TODO: Error if no project loaded
        if idx == 0:
            self.on_recover_fsm_clicked()
        else:
            raise NotImplementedError
