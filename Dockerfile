FROM python:3
WORKDIR /src

COPY . .
RUN pip install -r requirements.txt
CMD ["python", "./app.py"]