# GCP Cloud Function for Serverless Threat Remediation

resource "google_cloudfunctions_function" "soar_storage_remediator" {
  name        = "gcp-remediate-storage"
  description = "Remediates public Cloud Storage IAM bindings"
  runtime     = "python311"
  region      = "us-central1"

  entry_point = "handler"
  timeout     = 60
}
