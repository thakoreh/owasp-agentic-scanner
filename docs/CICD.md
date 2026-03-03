# CI/CD Integration

## GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install scanner
        run: pip install owasp-agentic-scanner

      - name: Run OWASP scan
        run: owasp-scan scan src --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## GitLab CI

```yaml
security-scan:
  image: python:3.12
  script:
    - pip install owasp-agentic-scanner
    - owasp-scan scan src --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Azure DevOps

```yaml
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.12'

- script: |
    pip install owasp-agentic-scanner
    owasp-scan scan src --format sarif --output $(Build.ArtifactStagingDirectory)/results.sarif
  displayName: 'Run OWASP Scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: $(Build.ArtifactStagingDirectory)/results.sarif
    artifactName: security-results
```

## Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install owasp-agentic-scanner'
                sh 'owasp-scan scan src --format json --output results.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.json'
                }
            }
        }
    }
}
```
