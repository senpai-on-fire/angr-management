from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from functools import partial
from typing import TYPE_CHECKING, Any

import angr
import claripy
from networkx.drawing.nx_agraph import write_dot
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from angrmanagement.ui.widgets.qproperty_editor import (
    BoolPropertyItem,
    ComboPropertyItem,
    GroupPropertyItem,
    IntPropertyItem,
    PropertyModel,
    QPropertyEditor,
    TextPropertyItem,
)

from .state_graph_recovery import AbstractStateFields, StateGraphRecoveryAnalysis
from .state_graph_recovery_job import StateGraphRecoveryJob

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

log = logging.getLogger(name=__name__)


class TaverenConfigItem(QTreeWidgetItem):
    def __init__(self, name: str, variable_name: str, parent=None):
        super().__init__([name])
        self.variable_name = variable_name
        self.parent = parent


class TaverenConfigVariableItem(QTreeWidgetItem):
    def __init__(self, idx: int, variable_name: str):
        self.idx = idx
        self.variable_name = variable_name
        super().__init__([self.get_display_name()])

    def get_display_name(self) -> str:
        return f"{self.idx} {self.variable_name}"


class TaverenConfigMMIOItem(QTreeWidgetItem):
    def __init__(self, idx: int, addr: int, size: int):
        self.idx = idx
        self.addr = addr
        self.size = size
        self.variable_name = f"MMIO_{addr:#x}"  # dummy
        super().__init__([self.get_display_name()])

    def get_display_name(self) -> str:
        return f"{self.idx} {self.addr:#x} ({self.size} bytes)"


class TaverenBoolPropertyItem(BoolPropertyItem):
    def __init__(self, name: str, value: bool, entry_name: str, key: tuple, **kwargs):
        super().__init__(name, value, **kwargs)
        self.entry_name = entry_name
        self.entry_type = bool
        self.key = key


class TaverenIntPropertyItem(IntPropertyItem):
    def __init__(self, name: str, value: int, entry_name: str, key: tuple, **kwargs):
        super().__init__(name, value, **kwargs)
        self.entry_name = entry_name
        self.entry_type = int
        self.key = key


class TaverenTextPropertyItem(TextPropertyItem):
    def __init__(self, name: str, value: str, entry_name: str, key: tuple, **kwargs):
        super().__init__(name, value, **kwargs)
        self.entry_name = entry_name
        self.entry_type = str
        self.key = key


class TaverenComboPropertyItem(ComboPropertyItem):
    def __init__(self, name: str, value: str, choices: list[str], entry_name: str, key: tuple, **kwargs):
        super().__init__(name, value, choices, **kwargs)
        self.entry_name = entry_name
        self.entry_type = str
        self.key = key


def hex_or_string(s: str | int | None) -> int | str | None:
    if s is None:
        return s
    if isinstance(s, str):
        s = s.strip()
        if s.startswith("0x"):
            return int(s, 16)
    return s


def hex_or_int(s: str | int | None) -> int:
    if s is None:
        return 0
    if isinstance(s, int):
        return s
    if isinstance(s, str):
        s = s.strip()
        if s.startswith("0x"):
            try:
                return int(s, 16)
            except ValueError:
                return 0
    return 0


class RecoverFSMDialog(QDialog):
    """
    Dialog that allows the user to run a target with a specific environment and executor.
    """

    def __init__(self, workspace: Workspace, config: dict[str, Any] | None = None):
        super().__init__()
        self.setWindowFlags(
            Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint | Qt.WindowType.WindowMinimizeButtonHint
        )
        self.setWindowTitle("Taveren: Recover an FSM")
        # FIXME: Icon
        # angr_icon_location = os.path.join(IMG_LOCATION, "angr.png")
        # self.setWindowIcon(QIcon(angr_icon_location))

        self.setMinimumWidth(1200)
        self.setMinimumHeight(600)

        self.config: dict[str, Any] = config if config is not None else {}
        self.workspace = workspace

        self._init_widgets()

    def _init_widgets(self):

        # Toolbar
        action_add_var = QAction("Add Variable", self)
        action_add_var.setStatusTip("Add a new variable")
        action_add_var.triggered.connect(self._on_add_variable_triggered)

        action_remove_var = QAction("Remove Variable", self)
        action_remove_var.setStatusTip("Remove the selected variable")
        action_remove_var.triggered.connect(self._on_remove_variable_triggered)

        action_add_mmio = QAction("Add MMIO Setup", self)
        action_add_mmio.setStatusTip("Add a new MMIO setup entry")
        action_add_mmio.triggered.connect(self._on_add_mmio_setup_triggered)

        action_remove_mmio = QAction("Remove MMIO Setup", self)
        action_remove_mmio.setStatusTip("Remove the selected MMIO setup entry")
        action_remove_mmio.triggered.connect(self._on_remove_mmio_setup_triggered)

        toolbar = QToolBar()
        toolbar.addAction(action_add_var)
        toolbar.addAction(action_remove_var)
        toolbar.addSeparator()
        toolbar.addAction(action_add_mmio)
        toolbar.addAction(action_remove_mmio)
        toolbar.addSeparator()

        # Load JSON file
        lbl_load_json = QLabel("Load Configuration (JSON):")
        self.txt_load_json = QLineEdit()
        btn_browse_json = QPushButton("...")
        btn_browse_json.setFixedWidth(30)
        btn_browse_json.clicked.connect(self._on_browse_json_clicked)
        btn_load_json = QPushButton("Load")
        btn_load_json.clicked.connect(self._on_load_json_clicked)

        hbox_load_json = QHBoxLayout()
        hbox_load_json.addWidget(lbl_load_json)
        hbox_load_json.addWidget(self.txt_load_json)
        hbox_load_json.addWidget(btn_browse_json)
        hbox_load_json.addWidget(btn_load_json)

        # Graph save location
        lbl_save_dot = QLabel("Save State Graph (DOT):")
        self.txt_save_dot = QLineEdit()
        btn_browse_dot = QPushButton("...")
        btn_browse_dot.setFixedWidth(30)
        btn_browse_dot.clicked.connect(self._on_browse_save_dot_clicked)
        hbox_save_dot = QHBoxLayout()
        hbox_save_dot.addWidget(lbl_save_dot)
        hbox_save_dot.addWidget(self.txt_save_dot)
        hbox_save_dot.addWidget(btn_browse_dot)

        #
        # Configuration
        #

        self.config_tree = QTreeWidget()
        self._init_config_tree()
        self.config_tree.itemClicked.connect(self._on_config_tree_item_clicked)

        self.config_properties = QPropertyEditor()

        splitter = QSplitter()
        splitter.addWidget(self.config_tree)
        splitter.addWidget(self.config_properties)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        # run analysis
        self.run_button = QPushButton("Start Analysis")
        self.run_button.clicked.connect(self._on_start_analysis)
        # close dialog
        close_button = QPushButton("Save and Close")
        close_button.clicked.connect(self.close)

        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(self.run_button)
        buttons.addWidget(close_button)
        buttons.addStretch()

        layout = QVBoxLayout()
        layout.addWidget(toolbar)
        layout.addWidget(splitter)
        layout.addLayout(hbox_load_json)
        layout.addLayout(hbox_save_dot)
        layout.addLayout(buttons)

        self.setLayout(layout)

    def _init_config_tree(self):
        self.config_tree.clear()
        self.config_tree.setColumnCount(1)
        self.config_tree.setHeaderHidden(True)

        entries = [
            ("Time Variable Address", "time_addr"),
            ("Scan Cycle Function", "scan_cycle_function"),
            ("Initializer Function", "initializer_function"),
            ("Initializer: Memory-Mapped I/O Setup", "initializer_mmio_setup"),
            ("Software", "software"),
            ("Variables", "variables"),
        ]

        items = []
        for name, varname in entries:
            item = TaverenConfigItem(name, varname, parent=None)
            items.append(item)
            if varname == "variables":
                # insert variables in json
                vars_list = self.config.get("variables", [])
                for varid, var in enumerate(vars_list):
                    varname = var.get("name", "<unnamed>")
                    var_item = TaverenConfigVariableItem(varid, varname)
                    item.addChild(var_item)
            elif varname == "initializer_mmio_setup":
                # insert MMIO setups
                mmio_list = self.config.get("initializer_mmio_setup", [])
                for mmioid, mmio in enumerate(mmio_list):
                    addr = hex_or_string(mmio.get("address", 0))
                    size = hex_or_string(mmio.get("size", 1))
                    # value = hex_or_string(mmio.get("value", 0))
                    # igger = hex_or_string(mmio.get("trigger", 0))
                    mmio_item = TaverenConfigMMIOItem(mmioid, addr, size)
                    item.addChild(mmio_item)
        self.config_tree.insertTopLevelItems(0, items)
        self.config_tree.expandAll()

    def _create_scan_cycle_properties(self, root, func_name: str):
        root.addChild(
            TaverenTextPropertyItem("Function Name", func_name, "scan_cycle_function", ("scan_cycle_function",))
        )

    def _create_initializer_properties(self, root, func_name: str, early_exit: str):
        root.addChild(
            TaverenTextPropertyItem("Function Name", func_name, "initializer_function", ("initializer_function",))
        )
        root.addChild(
            TaverenTextPropertyItem(
                "Execute Until... (optional)",
                early_exit,
                "initializer_function_early_exit",
                ("initializer_function_early_exit",),
            )
        )

    def _create_software_properties(self, root, software: str):
        root.addChild(
            TaverenComboPropertyItem(
                "Software", software, ["beremiz", "arduino", "simulink", "escape32"], "software", ("software",)
            )
        )

    def _create_time_addr_properties(self, root, time_addr: int | str | None):
        root.addChild(
            TaverenBoolPropertyItem(
                "Has Time Variable", time_addr is not None and time_addr != "", "has_time", ("time_addr",)
            )
        )
        root.addChild(
            TaverenIntPropertyItem("Value", time_addr if time_addr else 0, "time_addr", ("time_addr",), show_hex=True)
        )

    def _create_variable_properties(self, root, var_idx: int, props: dict[str, str | int]):
        children = []
        key = "variables", var_idx
        children.append(TaverenTextPropertyItem("Name", "", "name", key))
        children.append(TaverenIntPropertyItem("Address", 0, "address", key, show_hex=True))
        children.append(TaverenIntPropertyItem("Size", 1, "size", key, minimum=1, maximum=8))
        children.append(TaverenIntPropertyItem("Bit Offset", 0, "bit_pos_start", key, minimum=0, maximum=7))
        children.append(TaverenIntPropertyItem("Bit Offset End", 0, "bit_pos_end", key, minimum=0, maximum=7))
        children.append(TaverenComboPropertyItem("Sort", "int", ["int", "float", "double", "bool"], "sort", key))
        children.append(
            TaverenComboPropertyItem("Type", "input", ["input", "statevar", "output"], "type", key, editable=True)
        )

        for prop in children:
            if prop.entry_name in props:
                prop.value = props[prop.entry_name]
            root.addChild(prop)

    def _create_mmio_properties(self, root, mmio_idx: int, props: dict[str, str | int]):
        children = []
        key = "initializer_mmio_setup", mmio_idx
        children.append(TaverenIntPropertyItem("Address", 0, "address", key, show_hex=True))
        children.append(TaverenIntPropertyItem("Size (in bytes)", 1, "size", key, minimum=1, maximum=8))
        children.append(TaverenIntPropertyItem("Value", 0, "value", key, show_hex=True))
        children.append(TaverenIntPropertyItem("Trigger Address", 0, "trigger", key, show_hex=True))

        for prop in children:
            if prop.entry_name in props:
                prop.value = hex_or_int(props[prop.entry_name])
            root.addChild(prop)

    def add_variable(self, addr: int | None, size: int | None = None):
        if "variables" not in self.config:
            self.config["variables"] = []
        d = {}
        if addr is not None:
            d["address"] = addr
            d["size"] = size if size is not None else 1
        self.config["variables"].append(d)
        self._init_config_tree()

        # select the right item
        for i in range(self.config_tree.topLevelItemCount()):
            item = self.config_tree.topLevelItem(i)
            assert isinstance(item, TaverenConfigItem)
            if item.variable_name == "variables" and item.childCount() > 0:
                child_id = item.childCount() - 1
                self.config_tree.setCurrentItem(item.child(child_id))
                self._on_config_tree_item_clicked(item.child(child_id))
                break

    def add_mmio_setup(self, addr: int | None, size: int | None = None):
        if "initializer_mmio_setup" not in self.config:
            self.config["initializer_mmio_setup"] = []
        d = {}
        if addr is not None:
            d["address"] = addr
            d["size"] = size if size is not None else 1
        self.config["initializer_mmio_setup"].append(d)
        self._init_config_tree()

        # select the right item
        for i in range(self.config_tree.topLevelItemCount()):
            item = self.config_tree.topLevelItem(i)
            assert isinstance(item, TaverenConfigItem)
            if item.variable_name == "initializer_mmio_setup" and item.childCount() > 0:
                child_id = item.childCount() - 1
                self.config_tree.setCurrentItem(item.child(child_id))
                self._on_config_tree_item_clicked(item.child(child_id))
                break

    #
    # Event handlers and callbacks
    #

    def _on_add_variable_triggered(self):
        self.add_variable(None)

    def _on_remove_variable_triggered(self):
        selected_items = self.config_tree.selectedItems()
        if not selected_items:
            QMessageBox.critical(self, "Taveren: Remove Variable Error", "No variable is selected.")
            return
        item = selected_items[0]
        if not isinstance(item, TaverenConfigVariableItem):
            QMessageBox.critical(self, "Taveren: Remove Variable Error", "No variable is selected.")
            return
        var_idx = item.idx
        vars_list = self.config.get("variables", [])
        if 0 <= var_idx < len(vars_list):
            del vars_list[var_idx]
            self.config["variables"] = vars_list
            self._init_config_tree()

    def _on_add_mmio_setup_triggered(self):
        self.add_mmio_setup(None)

    def _on_remove_mmio_setup_triggered(self):
        selected_items = self.config_tree.selectedItems()
        if not selected_items:
            QMessageBox.critical(self, "Taveren: Remove MMIO Setup Error", "No MMIO setup entry is selected.")
            return
        item = selected_items[0]
        if not isinstance(item, TaverenConfigMMIOItem):
            QMessageBox.critical(self, "Taveren: Remove MMIO Setup Error", "No MMIO setup entry is selected.")
            return
        var_idx = item.idx
        mmio_list = self.config.get("initializer_mmio_setup", [])
        if 0 <= var_idx < len(mmio_list):
            del mmio_list[var_idx]
            self.config["initializer_mmio_setup"] = mmio_list
            self._init_config_tree()

    def _on_config_tree_item_clicked(self, item):

        assert isinstance(item, TaverenConfigItem | TaverenConfigVariableItem | TaverenConfigMMIOItem)

        # update details in the property editor
        root = GroupPropertyItem("Root")
        if item.variable_name == "time_addr":
            self._create_time_addr_properties(root, self.config.get("time_addr", None))
        elif item.variable_name == "scan_cycle_function":
            self._create_scan_cycle_properties(root, self.config.get("scan_cycle_function", "_start"))
        elif item.variable_name == "initializer_function":
            self._create_initializer_properties(
                root,
                self.config.get("initializer_function", ""),
                self.config.get("initializer_function_early_exit", ""),
            )
        elif item.variable_name == "software":
            self._create_software_properties(root, self.config.get("software", "beremiz"))
        elif isinstance(item, TaverenConfigVariableItem):
            vars_list = self.config.get("variables", [])
            while item.idx >= len(vars_list):
                vars_list.append({})
            var_props = vars_list[item.idx]
            self._create_variable_properties(root, item.idx, var_props)
        elif isinstance(item, TaverenConfigMMIOItem):
            mmio_list = self.config.get("initializer_mmio_setup", [])
            while item.idx >= len(mmio_list):
                mmio_list.append({})
            mmio_props = mmio_list[item.idx]
            self._create_mmio_properties(root, item.idx, mmio_props)
        else:
            return

        model = PropertyModel(root)

        model.valueChanged.connect(partial(self._on_config_properties_value_changed, root))

        self.config_properties.setModel(model)

    def _on_config_properties_value_changed(
        self,
        root: GroupPropertyItem,
        prop: TaverenTextPropertyItem | TaverenIntPropertyItem | TaverenBoolPropertyItem | TaverenComboPropertyItem,
        value: int | bool | str,
    ):
        # find the entry in self.config and update it
        if not prop.key:
            raise NotImplementedError
        if prop.key[0] == "time_addr":
            match prop.entry_name:
                case "has_time":
                    if value is False and "time_addr" in self.config:
                        self.config["time_addr"] = ""
                    elif value is True:
                        time_addr = next(
                            child
                            for child in root.children
                            if isinstance(child, TaverenIntPropertyItem) and child.entry_name == "time_addr"
                        ).value
                        self.config["time_addr"] = time_addr
                case "time_addr":
                    self.config["time_addr"] = value
                    has_time = next(
                        child
                        for child in root.children
                        if isinstance(child, TaverenBoolPropertyItem) and child.entry_name == "has_time"
                    )
                    has_time.value = True
        elif prop.key[0] == "software":
            self.config["software"] = value
        elif prop.key[0] == "scan_cycle_function":
            self.config["scan_cycle_function"] = value
        elif prop.key[0] == "initializer_function":
            self.config["initializer_function"] = value
        elif prop.key[0] == "initializer_function_early_exit":
            self.config["initializer_function_early_exit"] = value
        elif prop.key[0] == "initializer_mmio_setup":
            setup_idx = prop.key[1]
            if "initializer_mmio_setup" not in self.config:
                self.config["initializer_mmio_setup"] = []
            setup_list: list = self.config["initializer_mmio_setup"]
            while setup_idx >= len(setup_list):
                setup_list.append({})
            setup_props: dict = setup_list[setup_idx]
            setup_props[prop.entry_name] = value
            self.config["initializer_mmio_setup"] = setup_list

            # update MMIO setup entries in the config tree
            if prop.entry_name in {"address", "size"}:
                for i in range(self.config_tree.topLevelItemCount()):
                    top_item = self.config_tree.topLevelItem(i)
                    if isinstance(top_item, TaverenConfigItem) and top_item.variable_name == "initializer_mmio_setup":
                        for j in range(top_item.childCount()):
                            child_item = top_item.child(j)
                            if isinstance(child_item, TaverenConfigMMIOItem) and child_item.idx == setup_idx:
                                child_item.addr = hex_or_int(setup_props.get("address", 0))
                                child_item.size = hex_or_int(setup_props.get("size", 0))
                                child_item.setText(0, child_item.get_display_name())
                                break
                        break
        elif prop.key[0] == "variables":
            var_idx = prop.key[1]
            if "variables" not in self.config:
                self.config["variables"] = []
            vars_list: list = self.config["variables"]
            while var_idx >= len(vars_list):
                vars_list.append({})
            var_props: dict = vars_list[var_idx]
            var_props[prop.entry_name] = value
            self.config["variables"] = vars_list

            # update the variable name in the config tree
            if prop.entry_name in {"name"}:
                for i in range(self.config_tree.topLevelItemCount()):
                    top_item = self.config_tree.topLevelItem(i)
                    if isinstance(top_item, TaverenConfigItem) and top_item.variable_name == "variables":
                        for j in range(top_item.childCount()):
                            child_item = top_item.child(j)
                            if isinstance(child_item, TaverenConfigVariableItem) and child_item.idx == var_idx:
                                child_item.variable_name = value
                                child_item.setText(0, child_item.get_display_name())
                                break
                        break

    def _on_browse_json_clicked(self):
        # open a file dialog to select a JSON file
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Taveren: Open a Configuration File...",
            "",
            "JSON file (*.json);;All files (*.*)",
        )

        if file_path:
            self.txt_load_json.setText(file_path)

    def _on_browse_save_dot_clicked(self):
        # open a file dialog to select a DOT file
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Taveren: Save State Graph As...",
            "",
            "DOT file (*.dot);;All files (*.*)",
        )

        if file_path:
            self.txt_save_dot.setText(file_path)

    def _on_load_json_clicked(self):
        file_path = self.txt_load_json.text()
        if not os.path.isfile(file_path):
            QMessageBox.critical(self, "Taveren: Configuration File Error", "The specified file does not exist.")
            return

        try:
            with open(file_path) as f:
                data = json.load(f)
            log.info("Configuration loaded successfully from %s", file_path)
        except Exception as ex:
            log.error("Failed to load JSON file: %s", ex)
            return

        # compatibility
        variable_baseaddr = 0
        if "variable_base_addr" in data:
            variable_baseaddr = data["variable_base_addr"]
            if isinstance(variable_baseaddr, str):
                variable_baseaddr = int(variable_baseaddr, 16)
            del data["variable_base_addr"]

        for varprops in data.get("variables", []):
            if "address" in varprops:
                addr = varprops["address"]
                if isinstance(addr, str):
                    addr = int(addr, 16)
                varprops["address"] = addr + variable_baseaddr

        if isinstance(data.get("time_addr", 0), str) and data["time_addr"]:
            time_addr = int(data["time_addr"], 16)
            data["time_addr"] = time_addr

        # set the value in self.config to the loaded data
        self.config.clear()
        self.config.update(data)
        self._init_config_tree()

    @staticmethod
    def _hook_symbols(proj):
        # FIXME:

        func_names = [
            "PYTHON_EVAL_body__",
            "PYTHON_POLL_body__",
            "__publish_debug",
            "__publish_py_ext",
        ]

        ret_unconstrained = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
        for func_name in func_names:
            if func_name in proj.kb.functions:
                proj.hook(proj.kb.functions[func_name].addr, ret_unconstrained())

    def _create_initial_state(
        self,
        proj,
        initializer_func_name: str | int,
        initializer_func_early_exit: int | None = None,
        mmio_setup: list | None = None,
    ):
        # run the state initializer
        init = proj.kb.functions[initializer_func_name]
        state = proj.factory.blank_state(
            addr=init.addr, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.SIMPLIFY_CONSTRAINTS}
        )

        trigger_addr_to_mmio_setup = defaultdict(list)
        if mmio_setup is not None:
            for mmio in mmio_setup:
                trigger_addr_to_mmio_setup[mmio["trigger"]].append(mmio)

        state.regs.sp = 0x7FFF0000
        ret_trap = 0xDEADBEEE
        if self.workspace.main_instance.project.arch.call_pushes_ret:
            state.stack_push(claripy.BVV(ret_trap, self.workspace.main_instance.project.arch.bits))
        else:
            # set up the link register for the return address
            state.regs.lr = ret_trap

        simgr = proj.factory.simgr(state)
        while simgr.active:
            if len(simgr.active) > 1:
                # drop all but the first state
                simgr.active = [simgr.active[0]]

            s = simgr.active[0]
            # set up MMIOs properly
            if s.addr in trigger_addr_to_mmio_setup:
                for mmio in trigger_addr_to_mmio_setup[s.addr]:
                    s.memory.store(
                        mmio["address"], claripy.BVV(mmio["value"], mmio["size"] * 8), endness=proj.arch.memory_endness
                    )
            if initializer_func_early_exit is not None and s.addr == initializer_func_early_exit:
                break
            if s.addr == ret_trap:
                break
            simgr.step()
        return simgr.active[0]

    @staticmethod
    def _generate_field_desc(data, base_addr: int):
        # define abstract fields
        fields_desc = {}
        config_fields = {}
        input_fields = {}
        for variable in data["variables"]:
            if variable["type"] == "output" or variable["type"] == "statevar":
                fields_desc[variable["name"]] = (
                    base_addr + variable["address"],
                    variable.get("sort", "int"),
                    variable["size"],
                )
            elif variable["type"] == "config":
                config_fields[variable["name"]] = (
                    base_addr + variable["address"],
                    variable.get("sort", "int"),
                    variable["size"],
                )
            elif variable["type"] == "input":
                input_fields[variable["name"]] = (
                    base_addr + variable["address"],
                    variable.get("sort", "int"),
                    variable["size"],
                )

        return fields_desc, config_fields, input_fields

    @staticmethod
    def _switch_on(data, base_addr, proj, state):
        switch = next(x for x in data["variables"] if x["name"] == "SWITCH_BUTTON")
        switch_value_addr = base_addr + switch["address"]
        switch_flag_addr = switch_value_addr + 1
        state.memory.store(switch_value_addr, claripy.BVV(0x1, 8), endness=proj.arch.memory_endness)  # value
        state.memory.store(switch_flag_addr, claripy.BVV(0x2, 8), endness=proj.arch.memory_endness)  # flag

    def _on_state_graph_recovery_finished(self, sgr: StateGraphRecoveryAnalysis):

        g = sgr.state_graph
        # dump the graph to a file
        save_path = self.txt_save_dot.text().strip()
        write_dot(g, save_path)

        QMessageBox.information(self, "Taveren: Analysis Finished", f"State graph is saved to {save_path}.")

        self.run_button.setEnabled(True)

    def _on_start_analysis(self):
        # start the analysis using state graph recovery

        save_path = self.txt_save_dot.text()
        if not save_path.strip():
            QMessageBox.critical(
                self, "Taveren: Save File Error", "Please specify a valid file path to save the state graph."
            )
            return

        self.run_button.setEnabled(False)

        proj = self.workspace.main_instance.project
        # cfg = self.workspace.main_instance.kb.cfgs.get_most_accurate()

        data = self.config

        scan_cycle_func_name = hex_or_string(data["scan_cycle_function"])
        initializer_func_name = data["initializer_function"]
        initializer_func_early_exit = hex_or_string(data.get("initializer_function_early_exit", None))
        # mmio initializers
        mmio_setup = data.get("initializer_mmio_setup", [])
        for mmio in mmio_setup:
            mmio["address"] = hex_or_string(mmio["address"])
            mmio["value"] = hex_or_string(mmio["value"])
            mmio["size"] = hex_or_string(mmio["size"])
            mmio["trigger"] = hex_or_string(mmio["trigger"])

        self._hook_symbols(proj)
        initial_state = self._create_initial_state(
            proj, initializer_func_name, initializer_func_early_exit=initializer_func_early_exit, mmio_setup=mmio_setup
        )
        assert initial_state is not None

        base_addr = 0  # TODO: Get rid of it
        time_addr = data.get("time_addr", None)
        software = data["software"]

        # define abstract fields
        fields_desc, config_fields, input_fields = self._generate_field_desc(data, base_addr)

        # pre-constrain configuration variables so that we can track them
        config_vars = {}
        symbolic_config_var_to_fields = {}
        for var_name, (var_addr, var_type, var_size) in config_fields.items():
            # print("[.] Preconstraining %s..." % var_name)
            symbolic_v = claripy.BVS(var_name, var_size * 8)
            concrete_v = initial_state.memory.load(var_addr, size=var_size, endness=proj.arch.memory_endness)
            initial_state.memory.store(var_addr, symbolic_v, endness=proj.arch.memory_endness)
            initial_state.preconstrainer.preconstrain(concrete_v, symbolic_v)
            config_vars[var_name] = symbolic_v
            symbolic_config_var_to_fields[symbolic_v] = var_name, var_addr, var_type, var_size

        fields = AbstractStateFields(fields_desc)
        # abstract_input_fields = AbstractStateFields(input_fields)
        if scan_cycle_func_name in proj.kb.functions:
            func = proj.kb.functions[scan_cycle_func_name]
            start_addr = func.addr
        elif isinstance(scan_cycle_func_name, int):
            start_addr = scan_cycle_func_name
        else:
            raise ValueError(f"Cannot find the scan cycle address {scan_cycle_func_name}")

        job = StateGraphRecoveryJob(
            self.workspace.main_instance,
            start_addr,
            fields,
            software,
            time_addr=time_addr,
            init_state=initial_state,
            switch_on=(
                partial(self._switch_on, data, base_addr, proj) if data.get("switch_on", "False") == "True" else None
            ),
            config_vars=set(config_vars.values()),
            input_data=input_fields,
            on_finish=self._on_state_graph_recovery_finished,
            blocking=True,
        )
        self.workspace.job_manager.add_job(job)
