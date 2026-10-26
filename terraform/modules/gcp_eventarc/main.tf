# GCP Eventarc Trigger for Cloud Audit Telemetry

resource "google_eventarc_trigger" "gcp_storage_security_trigger" {
  name     = "soar-gcp-storage-trigger"
  location = "us-central1"

  matching_criteria {
    attribute = "type"
    value     = "google.cloud.audit.log.v1.written"
  }

  destination {
    cloud_function = "gcp-remediate-storage"
  }
}
