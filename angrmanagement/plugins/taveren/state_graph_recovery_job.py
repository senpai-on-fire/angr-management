from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from angrmanagement.data.jobs.job import InstanceJob, JobState

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class StateGraphRecoveryJob(InstanceJob):
    """
    The job for running the state graph recovery analysis.
    """

    def __init__(
        self,
        instance: Instance,
        start_addr: int,
        fields,
        software: str,
        *,
        time_addr: int | None,
        init_state=None,
        switch_on: Callable | None = None,
        config_vars: set | None = None,
        input_data: dict | None = None,
        on_finish=None,
        blocking: bool = False,
        **kwargs,
    ) -> None:
        super().__init__("FSM Recovery", instance, on_finish=on_finish, blocking=blocking)
        self.kwargs = kwargs

        self.start_addr = start_addr
        self.fields = fields
        self.software = software
        self.time_addr = time_addr
        self.init_state = init_state
        self.switch_on = switch_on
        self.config_vars = config_vars
        self.input_data = input_data if input_data is not None else {}

    def _check_job_state(self) -> bool:
        return self.state != JobState.CANCELLED

    def run(self, ctx: JobContext) -> None:
        sgr = self.instance.project.analyses.StateGraphRecovery(
            self.start_addr,
            self.fields,
            self.software,
            self.time_addr,
            init_state=self.init_state,
            switch_on=self.switch_on,
            config_vars=self.config_vars,
            input_data=self.input_data,
            low_priority=True,
            job_state_callback=self._check_job_state,
            progress_callback=ctx.set_progress,
        )
        return sgr
