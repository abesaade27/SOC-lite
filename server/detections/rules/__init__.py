"""Detection rules package exporting all SOC rules."""

from .auth_rules import SOC001BruteForceLogon, SOC002LogonAfterFailures
from .account_rules import (
    SOC003LocalUserCreated,
    SOC004PrivilegedGroupMemberAdded,
    SOC011AccountLockout,
    SOC014RapidNewAccountAdminChain,
)
from .policy_rules import SOC005AuditLogCleared
from .service_task_rules import SOC006NewServiceInstalled, SOC009ScheduledTaskCreated
from .execution_process_rules import (
    SOC007EncodedPowerShell,
    SOC008LOLBinAbuse,
    SOC013SuspiciousParentChild,
)
from .credential_defender_rules import SOC010LSASSMemoryAccess, SOC012DefenderDisabled
from .endpoint_rules import (
    SOC015BrowserCredentialTheft,
    SOC016RunKeyPersistence,
    SOC017StartupFolderDrop,
    SOC018OutboundLOLBinConnection,
    SOC019RansomwareCanary,
    SOC020IOCMatchedOrRenamedTool,
)

ALL_RULES = [
    SOC001BruteForceLogon(),
    SOC002LogonAfterFailures(),
    SOC003LocalUserCreated(),
    SOC004PrivilegedGroupMemberAdded(),
    SOC005AuditLogCleared(),
    SOC006NewServiceInstalled(),
    SOC007EncodedPowerShell(),
    SOC008LOLBinAbuse(),
    SOC009ScheduledTaskCreated(),
    SOC010LSASSMemoryAccess(),
    SOC011AccountLockout(),
    SOC012DefenderDisabled(),
    SOC013SuspiciousParentChild(),
    SOC014RapidNewAccountAdminChain(),
    SOC015BrowserCredentialTheft(),
    SOC016RunKeyPersistence(),
    SOC017StartupFolderDrop(),
    SOC018OutboundLOLBinConnection(),
    SOC019RansomwareCanary(),
    SOC020IOCMatchedOrRenamedTool(),
]
