FROM ubuntu:latest

RUN apt-get -y update && \
    apt-get install -y curl python3 python3-pip

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir pwntools cryptography beautifulsoup4 requests

WORKDIR /exploit

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python3", "exploit.py" ]
