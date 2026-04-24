pipeline {
    agent any

    tools {
        // Must match Jenkins Global Tool Configuration names exactly
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