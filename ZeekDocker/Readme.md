# PcapZeekCsvDocker

This a docker container runs Zeek on a set of pcap files and converts chosen log files to csv format, such that it can easily be imported into a pandas Dataframe.

## Usage

To run the tool, clone the repository and run the following command:

```bash 
docker-compose up
```

In order to specify the log files that should be converted go to the Dockerfile and change the following line to your needs:

```bash
CMD ["python3", "/app/zeekautomation.py", "-i", "/home/pcaps", "-o", "/home/logs", "-l", "ssh.log", "conn.log"]
```

In this example we convert the ssh.log and conn.log files to csv format.
