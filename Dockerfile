FROM python:3.9
LABEL maintainer="millken <millken@gmail.com>"

RUN mkdir /usr/src/myapp -p
COPY . /usr/src/myapp
WORKDIR /usr/src/myapp
RUN pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

CMD [ "python", "server.py"]