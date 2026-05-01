pipeline {
agent any
tools {
    maven 'Maven'
    jdk 'JDK21'
}

options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(
        numToKeepStr: '10',
        artifactNumToKeepStr: '10'
    ))
    timeout(time: 30, unit: 'MINUTES')
}

environment {
    APP_NAME = 'password-strength-checker'
    APP_VERSION = '1.0.0'
    JAR_PATH = 'target/*.jar'
    IMAGE_NAME = 'santhr/password-checker'
    IMAGE_TAG = 'latest'
}

stages {

    stage('Checkout') {
        steps {
            echo '🔄 Pulling latest source code from GitHub...'
            checkout scm
        }
    }

    stage('Show Environment') {
        steps {
            echo '📌 Verifying Java and Maven versions...'
            bat 'java -version'
            bat 'mvn -version'
        }
    }

    stage('Clean') {
        steps {
            echo '🧹 Cleaning old build files...'
            bat 'mvn clean'
        }
    }

    stage('Compile') {
        steps {
            echo '🔨 Compiling project...'
            bat 'mvn compile'
        }
    }

    stage('Unit Test') {
        steps {
            echo '🧪 Running tests...'
            bat 'mvn test'
        }
        post {
            always {
                junit allowEmptyResults: true,
                      testResults: '**/target/surefire-reports/*.xml'
            }
        }
    }

    stage('SonarQube Analysis') {
        steps {
            echo '🔍 Running SonarQube analysis...'
            withSonarQubeEnv('SonarQube') {
                bat 'mvn sonar:sonar -Dsonar.projectKey=password-checker'
            }
        }
    }

    stage('Quality Gate') {
        steps {
            echo '⏳ Waiting for Quality Gate result...'
            timeout(time: 5, unit: 'MINUTES') {
                waitForQualityGate abortPipeline: true
            }
        }
    }

    stage('Package') {
        steps {
            echo '📦 Packaging application JAR...'
            bat 'mvn package -DskipTests'
        }
    }

    stage('Archive Artifacts') {
        steps {
            echo '🗄️ Archiving JAR artifact...'
            archiveArtifacts artifacts: "${JAR_PATH}",
                             fingerprint: true,
                             onlyIfSuccessful: true
        }
    }

    stage('Docker Build') {
        steps {
            echo '🐳 Building Docker image...'
            bat 'docker build -t %IMAGE_NAME%:%IMAGE_TAG% .'
        }
    }

    stage('Docker Push') {
        steps {
            echo '🚀 Pushing Docker image to DockerHub...'
            withCredentials([usernamePassword(
                credentialsId: 'docker-creds',
                usernameVariable: 'DOCKER_USER',
                passwordVariable: 'DOCKER_PASS'
            )]) {
                bat 'echo %DOCKER_PASS% | docker login -u %DOCKER_USER% --password-stdin'
                bat 'docker push %IMAGE_NAME%:%IMAGE_TAG%'
            }
        }
    }

    stage('Deploy') {
        steps {
            echo '🚀 Running Docker container locally...'
            bat 'docker stop password-app || exit 0'
            bat 'docker rm password-app || exit 0'
            bat 'docker run -d -p 8081:8443 --name password-app %IMAGE_NAME%:%IMAGE_TAG%'
        }
    }

    stage('Build Summary') {
        steps {
            echo "📌 Application : ${APP_NAME}"
            echo "📌 Version     : ${APP_VERSION}"
            echo "📌 Build No    : ${env.BUILD_NUMBER}"
            echo "📌 Job Name    : ${env.JOB_NAME}"
        }
    }
}

post {

    success {
        echo '✅ BUILD SUCCESSFUL'
    }

    failure {
        echo '❌ BUILD FAILED'
    }

    unstable {
        echo '⚠️ BUILD UNSTABLE'
    }

    always {
        echo '🧽 Cleaning Jenkins workspace...'
        cleanWs()
    }
}

}
