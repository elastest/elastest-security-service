# Development documentation

## Architecture

ESS is implemented in two parts:
* ESS Web client Application: A web-based GUI for interacting with the ESS API
* ESS Server Application: The back-end of the ESS API

## How to prepare the ESS development environment
The ESS is developed completely in Python (currently it is Python v2.7 compatible although v3 will be supported soon). The entire source code is available in the [ESS GitHub repository](https://github.com/elastest/elastest-security-service). As of v0.5.0, the core is ESS is in the file [ess.py](https://github.com/elastest/elastest-security-service/blob/master/ess.py). It is developed using the [python flask module](http://flask.pocoo.org/).

## Development procedure
A standard Python IDE (e.g. [PyCharm](https://www.jetbrains.com/pycharm/)) or a simple text editor such as VIM along with the python compiler is sufficient to run the code. Additional libraries that needs to be installed are listed [here](https://github.com/elastest/elastest-security-service/blob/master/requirements.txt). To execute the program, simply run the [ess.py](https://github.com/elastest/elastest-security-service/blob/master/ess.py) file.

## Docker images
The docker image associated to ESS is accessible [here](https://hub.docker.com/r/elastest/ess/).

## Continuous integration
1. The Jenkins file for the end-to-end test of ESS is accessible [here](https://github.com/elastest/elastest-security-service/blob/master/e2e-test/Jenkinsfile).
2. The Jenkins file for the ESS is accessible [here](https://github.com/elastest/elastest-security-service/blob/master/Jenkinsfile).
