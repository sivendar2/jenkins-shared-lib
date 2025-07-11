package org.devsecops

class GitHandler implements Serializable {

    static def createAutofixPR() {
        bat '''
            @echo off
            setlocal enabledelayedexpansion

            git config --global user.name "jenkins-bot"
            git config --global user.email "jenkins-bot@users.noreply.github.com"
            for /f %%i in ('powershell -Command "Get-Date -UFormat %%s"') do set BRANCH_NAME=fix/sast-autofix-%%i

            git checkout -b !BRANCH_NAME!
            git add .
            git diff --cached --quiet || git commit -m "chore: auto-remediation for SAST issues"
            git push https://%GIT_USER%:%GIT_PASS%@github.com/sivendar2/employee-department-1.git !BRANCH_NAME!

            gh pr create ^
              --base main ^
              --head !BRANCH_NAME! ^
              --title "SAST: Auto-fixed issues using Semgrep" ^
              --body "This PR includes automatic SAST fixes. Please review."
        '''
    }
}
