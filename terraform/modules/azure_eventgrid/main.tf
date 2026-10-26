# Azure Event Grid System Topic for Security Audit Events

resource "azurerm_eventgrid_system_topic" "security_events" {
  name                   = "soar-azure-security-events"
  location               = "eastus"
  resource_group_name    = "rg-security-soar"
  source_arm_resource_id = "/subscriptions/00000000-0000-0000-0000-000000000000"
  topic_type             = "Microsoft.Resources.Subscriptions"

  tags = {
    Environment = "Production"
    Engine      = "Azure-SOAR"
  }
}
