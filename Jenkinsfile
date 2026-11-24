pipeline {
    agent any

    environment {
        DEPLOY_DIR = "/opt/app-deploy"
        VENV_NAME = "venv"
    }

    stages {
        stage('1. Dependency Management') {
            steps {
                echo "==> [Jenkins] Verificando requirements.txt..."
                sh '''
                    if [ ! -f "requirements.txt" ]; then
                        echo "Error: No se encontró requirements.txt"
                        exit 1
                    fi
                    cat requirements.txt
                '''
            }
        }

        stage('2. Build') {
            steps {
                echo "==> [Jenkins] Creando entorno virtual e instalando dependencias..."
                sh '''
                    python3 -m venv ${VENV_NAME}
                    . ${VENV_NAME}/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('3. SAST (Bandit)') {
            steps {
                echo "==> [SAST] Ejecutando análisis estático con Bandit sobre app.py..."
                sh '''
                    . ${VENV_NAME}/bin/activate
                    bandit -r . -x ./${VENV_NAME} -f txt -o bandit-report.txt || true
                    cat bandit-report.txt
                '''
            }
        }

        stage('4. Test') {
            steps {
                echo "==> [Test] Verificando sintaxis de la aplicación..."
                sh '''
                    . ${VENV_NAME}/bin/activate
                    python3 -m py_compile app.py
                '''
            }
        }

        stage('5. Deploy & DAST (OWASP ZAP)') {
            steps {
                echo "==> [Deploy & DAST] Desplegando app y ejecutando OWASP ZAP..."
                sh '''
                    sudo mkdir -p ${DEPLOY_DIR}
                    sudo cp -r app.py requirements.txt ${DEPLOY_DIR}/

                    . ${VENV_NAME}/bin/activate
                    nohup python3 app.py > flask.log 2>&1 &
                    APP_PID=$!
                    sleep 4

                    docker run --rm --network="host" \
                        -e JAVA_OPTS="-Xmx512m" \
                        -v $(pwd):/zap/wrk/:rw \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py -t http://127.0.0.1:5000 -r zap-report.html || true

                    kill $APP_PID || true
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'bandit-report.txt, zap-report.html', allowEmptyArchive: true
        }
    }
}
