package org.devsecops

class SemgrepHandler implements Serializable {

    static def runScanWithAutofix() {
        def semgrepPath = "C:\\Users\\test\\AppData\\Local\\Programs\\Python\\Python313\\Scripts\\semgrep.exe"
        def configPath = ".semgrep/sql-injection-autofix.yml"

        sh """
            if [ ! -f ${configPath} ]; then
              echo "[ERROR] Semgrep config missing"
              exit 1
            fi

            ${semgrepPath} scan --config ${configPath} --autofix --json > semgrep-report.json || true
        """

        archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: false
    }
}
