# security-snyk-clojure-action

This action runs snyk on clojure repo, using `leningen` to generate a pom.xml file

For the V2 action add the following secrets: `TWINGATE_PUBLIC_REPO_KEY` in public repos and `TWINGATE_KEY` private repos

## Inputs

### snykToken (required)
This input is the secret snyk token

### snykOrg (not required)
The organization in snyk to send results to

### snykProject (not required)
The project name in snyk

### noMonitor (not required)
If you just want to run `snyk test` and not `snyk monitor` you should set this input to `true`

### snykTargetRef (not required - default: false)
If you set this value to `true`, when running snyk monitor the `--target-reference` argument will be set to the value of `GITHUB_REF_NAME` which is the branch or tag name that triggered the workflow run

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
