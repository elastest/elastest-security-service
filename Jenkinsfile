node('docker') {
    stage "Container Prep"
        echo("The node is up")
        def mycontainer = docker.image('elastest/ci-docker-compose-py-siblings:latest')
        mycontainer.pull()
        mycontainer.inside("-u jenkins -v /var/run/docker.sock:/var/run/docker.sock:rw") {
            git 'https://github.com/elastest/elastest-security-service'


            stage "Build image - Package"
                echo ("Building")
		sh 'docker build --build-arg GIT_COMMIT=$(git rev-parse HEAD) --build-arg COMMIT_DATE=$(git log -1 --format=%cd --date=format:%Y-%m-%dT%H:%M:%S) . -t elastest/ess'
                def myimage = docker.image 'elastest/ess'

            stage "Run image"
                myimage.run()

            stage "Publish"
                echo ("Publishing")
                withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'elastestci-dockerhub',
                    usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
                    sh 'docker login -u "$USERNAME" -p "$PASSWORD"'
                    myimage.push()
                }

	    stage "Cobertura"
                def codecovArgs = "-v -t $COB_ESS_TOKEN"
                echo "$codecovArgs"
                def exitCode = sh(
                    returnStatus: true,
                    script: "coverage run test_ess.py && curl -s https://codecov.io/bash | bash -s - $codecovArgs")
                    if (exitCode != 0) {
                        echo( exitCode +': Failed to upload code coverage to codecov')
                    }
        }
}
