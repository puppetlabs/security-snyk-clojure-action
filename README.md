# security-snyk-clojure-action

This action runs snyk on clojure repo, using `leningen` to generate a pom.xml file

## Inputs

### snykToken (required)
This input is the secret snyk token

### snykOrg (required)
The organization in snyk to send results to

### snykProject (required)
The project name in snyk

### rproxyKey (required)
The reverse proxy API key

### noMonitor (not required)
If you just want to run `snyk test` and not `snyk monitor` you should set this input to `true`

### snykPolicy (not required)
This is the path to a `.snyk` file in your repository to pass to snyk while running `snyk test`. Information on the file format can be found here: https://docs.snyk.io/features/fixing-and-prioritizing-issues/policies/the-.snyk-file . It can be used to ignore vulnerabilities or remove false positives.

## Outputs
### vulns
An comma separated list of vulnerable packages in the format `<package_name>: <snyk_id>|<cve IDs>`. Example:
```
foo: SNYK-JAVA-FOO-BLAH, com.fasterxml.jackson.dataformat:jackson-dataformat-cbor-2.9.0: SNYK-JAVA-COMFASTERXMLJACKSONDATAFORMAT-1047329|CVE-2020-28491, bar: SNYK-JAVA-bar-00000
```

## Example usage
plasee see `sample_workflow.yaml` for a sample