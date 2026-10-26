# Azure Logic App Workflow for Incident Containment

resource "azurerm_logic_app_workflow" "remediation_workflow" {
  name                = "soar-containment-logicapp"
  location            = "eastus"
  resource_group_name = "rg-security-soar"

  tags = {
    Environment = "Production"
    Playbook    = "EntraID-RevokeSession"
  }
}
