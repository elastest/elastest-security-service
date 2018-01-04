# ElasTest Security Service (ESS)

The ElasTest Security Service (ESS) is an ElasTest service for identifying security issues in the System Under Test (SuT) by mimicking attacker behavior. Thus, when finding security issues, the focus is not in generating test cases that capture normal user behavior with the SuT. Instead, ESS focuses on generating test cases that check the SuT reaction to abnormal behavior (e.g. modifying URL parameters, using incorrect requests, or replaying authorization requests).

## Features
The current version of ESS (v0.5.0) has the following features.
- A web-based GUI for Creating secJobs from tJobs defined in [ElasTest TORM](https://github.com/elastest/elastest-torm), Update and Delete secJobs
- Detect the insecure URLs and cookies involved in the tJob associated to a secJob

The future versions of the ESS is expected to support the detection of the following types of vulnerabilities/attacks:
- Logical vulnerability
- Denial-of-Service
- Improper/Missing authentication

## How to run

ESS can be installed by running the following documentation provided [here](https://docs.google.com/document/d/1bKEMpXKUAaE0Re7hNxCKY99D6HSuy96cwqZ5rQkEERs/edit?usp=sharing).

## Basic usage

When ElasTest ESS is started, its API is accessible in the following URL:
- Linux & Windows: http://localhost:80/
The API description is [available](http://elastest.io/docs/api/ess/).
