# security-snyk-clojure-action

This action runs snyk on clojure repo, using `leningen` to generate a pom.xml file

## Inputs

### snykToken (required)
This input is the secret snyk token

### snykOrg (required)
The organization in snyk to send results to

### snykProject (required)
The project name in snyk

### noMonitor (not required)
If you just want to run `snyk test` and not `snyk monitor` you should set this input to `true`

## Outputs
### vulns
An array of vulnerable packages

## Example usage
plasee see `sample_workflow.yaml` for a sample