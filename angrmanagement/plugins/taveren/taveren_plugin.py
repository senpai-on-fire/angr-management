from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from angrmanagement.plugins import BasePlugin

from .fsm_recovery_dialog import RecoverFSMDialog

if TYPE_CHECKING:
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

    def _on_add_mmio_entry_triggered(self, addr: int):
        dlg = RecoverFSMDialog(self.workspace, config=self.config)
        dlg.add_mmio_setup(addr)
        dlg.exec_()

    def _on_add_variable_triggered(self, addr: int):
        dlg = RecoverFSMDialog(self.workspace, config=self.config)
        dlg.add_variable(addr)
        dlg.exec_()

    # Menus

    def build_context_menu_label(self, addr: int):
        yield None  # separator
        yield "Taveren: Add as an MMIO entry...", partial(self._on_add_mmio_entry_triggered, addr),
        yield "Taveren: Add as a key variable...", partial(self._on_add_variable_triggered, addr),

    # Event handlers

    def handle_click_menu(self, idx: int):
        # TODO: Error if no project loaded
        if idx == 0:
            self.on_recover_fsm_clicked()
        else:
            raise NotImplementedError
