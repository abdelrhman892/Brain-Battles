FROM python:3.12.5



ADD . /app
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

EXPOSE 3000

ENV FLASK_APP=app.py
ENV FLASK_ENV=development

CMD python ./app.py