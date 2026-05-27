pipeline {
    agent any

    environment {
        APP_NAME = "password-checker"
        DOCKER_IMAGE = "santhr/password-checker:latest"

        EC2_USER = "ubuntu"
        EC2_HOST = "13.235.2.214"

        SSH_CREDENTIALS = "ec2-ssh-key"
        DOCKERHUB_CREDS = "docker-token"
    }

    tools {
        maven 'Maven'
    }

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(
            numToKeepStr: '10'
        ))
    }

    triggers {
        githubPush()
    }

    stages {

        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }

        stage('Checkout Code') {
            steps {
                git(
                    branch: 'main',
                    credentialsId: 'github-pat',
                    url: 'https://github.com/SanthoshiRavi/password-strength-detecter.git'
                )
            }
        }

        stage('Build Application') {
            steps {
                sh '''
                    echo "Building Spring Boot application..."
                    mvn clean package -DskipTests
                '''
            }
        }

        stage('Run Tests') {
            steps {
                sh '''
                    echo "Running tests..."
                    mvn test
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                    echo "Building Docker image..."
                    docker build -t $DOCKER_IMAGE .
                '''
            }
        }

        stage('Docker Hub Login') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: "${DOCKERHUB_CREDS}",
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {

                    sh '''
                        echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                    '''
                }
            }
        }

        stage('Push Docker Image') {
            steps {
                sh '''
                    echo "Pushing Docker image to Docker Hub..."
                    docker push $DOCKER_IMAGE
                '''
            }
        }

        stage('Deploy to EC2') {
            steps {

                sshagent(credentials: ["${SSH_CREDENTIALS}"]) {

                    sh '''
                        echo "Deploying application to EC2..."

                        ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_HOST} << EOF

                        docker pull ${DOCKER_IMAGE}

                        docker stop ${APP_NAME} || true
                        docker rm ${APP_NAME} || true

                        docker run -d \
                            --name ${APP_NAME} \
                            -p 8080:8080 \
                            --restart always \
                            ${DOCKER_IMAGE}

                        docker image prune -f

                        echo "Deployment completed successfully!"

EOF
                    '''
                }
            }
        }
    }

    post {

        success {
            echo 'CI/CD Pipeline executed successfully!'
        }

        failure {
            echo 'Pipeline failed. Check logs for details.'
        }

        always {
            cleanWs()
        }
    }
}