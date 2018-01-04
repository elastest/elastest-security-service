#From ZAP's docker image
FROM owasp/zap2docker-stable

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# Set Image Labels
ARG GIT_COMMIT=unspecified
LABEL git_commit=$GIT_COMMIT

ARG COMMIT_DATE=unspecified
LABEL commit_date=$COMMIT_DATE

ARG VERSION=unspecified
LABEL version=$VERSION 

USER root
# Install any needed packages specified in requirements.txt
RUN pip install flask

# Install any needed packages specified in requirements.txt
RUN pip install flask-httpauth

# Install any needed packages specified in requirements.txt
RUN pip install requests

# Make port 80 available to the world outside this container
EXPOSE 8000

#Run ZAP in daemon mode
RUN chmod +x ./../zap/zap.sh
CMD python ess.py & ./../zap/zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true &&fg


# Run app.py when the container launches
#CMD ["python", "ess.py"]
