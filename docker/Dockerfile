from adaptorel/u12.04_oracle-jdk-7_play-2.2.4

RUN git clone https://github.com/adaptorel/oauthorize.git

WORKDIR /oauthorize

RUN /opt/play/play clean stage

ENTRYPOINT target/universal/stage/bin/oauthorize-play-2-2
