FROM zeekurity/zeek:5.2.2
RUN apt-get update && apt-get install -y python3-pip
RUN pip3 install pandas
COPY . /app
CMD ["python3", "/app/zeekautomation.py", "-i", "/home/pcaps", "-o", "/home/logs", "-l", "ssh.log", "conn.log"]